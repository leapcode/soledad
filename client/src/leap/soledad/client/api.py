# -*- coding: utf-8 -*-
# api.py
# Copyright (C) 2013, 2014 LEAP
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
"""
Soledad - Synchronization Of Locally Encrypted Data Among Devices.

This module holds the public api for Soledad.

Soledad is the part of LEAP that manages storage and synchronization of
application data. It is built on top of U1DB reference Python API and
implements (1) a SQLCipher backend for local storage in the client, (2) a
SyncTarget that encrypts data before syncing, and (3) a CouchDB backend for
remote storage in the server side.
"""
import binascii
import errno
import httplib
import logging
import os
import socket
import ssl
import urlparse

try:
    import cchardet as chardet
except ImportError:
    import chardet

from u1db.remote import http_client
from u1db.remote.ssl_match_hostname import match_hostname
from zope.interface import implements

from twisted.python import log

from leap.common.config import get_path_prefix
from leap.soledad.common import SHARED_DB_NAME
from leap.soledad.common import soledad_assert
from leap.soledad.common import soledad_assert_type

from leap.soledad.client import adbapi
from leap.soledad.client import events as soledad_events
from leap.soledad.client import interfaces as soledad_interfaces
from leap.soledad.client.crypto import SoledadCrypto
from leap.soledad.client.secrets import SoledadSecrets
from leap.soledad.client.shared_db import SoledadSharedDatabase
from leap.soledad.client.sqlcipher import SQLCipherOptions, SQLCipherU1DBSync

logger = logging.getLogger(name=__name__)

#
# Constants
#

"""
Path to the certificate file used to certify the SSL connection between
Soledad client and server.
"""
SOLEDAD_CERT = None


class Soledad(object):
    """
    Soledad provides encrypted data storage and sync.

    A Soledad instance is used to store and retrieve data in a local encrypted
    database and synchronize this database with Soledad server.

    This class is also responsible for bootstrapping users' account by
    creating cryptographic secrets and/or storing/fetching them on Soledad
    server.

    Soledad uses ``leap.common.events`` to signal events. The possible events
    to be signaled are:

        SOLEDAD_CREATING_KEYS: emitted during bootstrap sequence when key
            generation starts.
        SOLEDAD_DONE_CREATING_KEYS: emitted during bootstrap sequence when key
            generation finishes.
        SOLEDAD_UPLOADING_KEYS: emitted during bootstrap sequence when soledad
            starts sending keys to server.
        SOLEDAD_DONE_UPLOADING_KEYS: emitted during bootstrap sequence when
            soledad finishes sending keys to server.
        SOLEDAD_DOWNLOADING_KEYS: emitted during bootstrap sequence when
            soledad starts to retrieve keys from server.
        SOLEDAD_DONE_DOWNLOADING_KEYS: emitted during bootstrap sequence when
            soledad finishes downloading keys from server.
        SOLEDAD_NEW_DATA_TO_SYNC: emitted upon call to C{need_sync()} when
          there's indeed new data to be synchronized between local database
          replica and server's replica.
        SOLEDAD_DONE_DATA_SYNC: emitted inside C{sync()} method when it has
            finished synchronizing with remote replica.
    """
    implements(soledad_interfaces.ILocalStorage,
               soledad_interfaces.ISyncableStorage,
               soledad_interfaces.ISecretsStorage)

    local_db_file_name = 'soledad.u1db'
    secrets_file_name = "soledad.json"
    default_prefix = os.path.join(get_path_prefix(), 'leap', 'soledad')

    def __init__(self, uuid, passphrase, secrets_path, local_db_path,
                 server_url, cert_file,
                 auth_token=None, defer_encryption=False, syncable=True):
        """
        Initialize configuration, cryptographic keys and dbs.

        :param uuid: User's uuid.
        :type uuid: str

        :param passphrase:
            The passphrase for locking and unlocking encryption secrets for
            local and remote storage.
        :type passphrase: unicode

        :param secrets_path:
            Path for storing encrypted key used for symmetric encryption.
        :type secrets_path: str

        :param local_db_path: Path for local encrypted storage db.
        :type local_db_path: str

        :param server_url:
            URL for Soledad server. This is used either to sync with the user's
            remote db and to interact with the shared recovery database.
        :type server_url: str

        :param cert_file:
            Path to the certificate of the ca used to validate the SSL
            certificate used by the remote soledad server.
        :type cert_file: str

        :param auth_token:
            Authorization token for accessing remote databases.
        :type auth_token: str

        :param defer_encryption:
            Whether to defer encryption/decryption of documents, or do it
            inline while syncing.
        :type defer_encryption: bool

        :param syncable:
            If set to ``False``, this database will not attempt to synchronize
            with remote replicas (default is ``True``)
        :type syncable: bool

        :raise BootstrapSequenceError:
            Raised when the secret generation and storage on server sequence
            has failed for some reason.
        """
        # store config params
        self._uuid = uuid
        self._passphrase = passphrase
        self._local_db_path = local_db_path
        self._server_url = server_url
        self._defer_encryption = defer_encryption
        self._secrets_path = None

        self.shared_db = None

        # configure SSL certificate
        global SOLEDAD_CERT
        SOLEDAD_CERT = cert_file

        # init crypto variables
        self._set_token(auth_token)
        self._crypto = SoledadCrypto(self)

        self._init_config_with_defaults()
        self._init_working_dirs()

        self._secrets_path = secrets_path

        # Initialize shared recovery database
        self.init_shared_db(server_url, uuid, self._creds, syncable=syncable)

        # The following can raise BootstrapSequenceError, that will be
        # propagated upwards.
        self._init_secrets()
        self._init_u1db_sqlcipher_backend()

        if syncable:
            self._init_u1db_syncer()

    #
    # initialization/destruction methods
    #
    def _init_config_with_defaults(self):
        """
        Initialize configuration using default values for missing params.
        """
        soledad_assert_type(self._passphrase, unicode)
        initialize = lambda attr, val: getattr(
            self, attr, None) is None and setattr(self, attr, val)

        initialize("_secrets_path", os.path.join(
            self.default_prefix, self.secrets_file_name))
        initialize("_local_db_path", os.path.join(
            self.default_prefix, self.local_db_file_name))
        # initialize server_url
        soledad_assert(self._server_url is not None,
                       'Missing URL for Soledad server.')

    def _init_working_dirs(self):
        """
        Create work directories.

        :raise OSError: in case file exists and is not a dir.
        """
        paths = map(lambda x: os.path.dirname(x), [
            self._local_db_path, self._secrets_path])
        for path in paths:
            create_path_if_not_exists(path)

    def _init_secrets(self):
        self._secrets = SoledadSecrets(
            self.uuid, self._passphrase, self._secrets_path,
            self.shared_db, self._crypto)
        self._secrets.bootstrap()

    def _init_u1db_sqlcipher_backend(self):
        """
        Initialize the U1DB SQLCipher database for local storage, by
        instantiating a modified twisted adbapi that will maintain a threadpool
        with a u1db-sqclipher connection for each thread, and will return
        deferreds for each u1db query.

        Currently, Soledad uses the default SQLCipher cipher, i.e.
        'aes-256-cbc'. We use scrypt to derive a 256-bit encryption key,
        and internally the SQLCipherDatabase initialization uses the 'raw
        PRAGMA key' format to handle the key to SQLCipher.
        """
        tohex = binascii.b2a_hex
        # sqlcipher only accepts the hex version
        key = tohex(self._secrets.get_local_storage_key())
        sync_db_key = tohex(self._secrets.get_sync_db_key())

        opts = SQLCipherOptions(
            self._local_db_path, key,
            is_raw_key=True, create=True,
            defer_encryption=self._defer_encryption,
            sync_db_key=sync_db_key,
        )
        self._soledad_opts = opts
        self._dbpool = adbapi.getConnectionPool(opts)

    def _init_u1db_syncer(self):
        replica_uid = self._dbpool.replica_uid
        print "replica UID (syncer init)", replica_uid
        self._dbsyncer = SQLCipherU1DBSync(
            self._soledad_opts, self._crypto, replica_uid,
            self._defer_encryption)

    #
    # Closing methods
    #

    def close(self):
        """
        Close underlying U1DB database.
        """
        logger.debug("Closing soledad")
        self._dbpool.close()

        # TODO close syncers >>>>>>

    #
    # ILocalStorage
    #

    def _defer(self, meth, *args, **kw):
        return self._dbpool.runU1DBQuery(meth, *args, **kw)

    def put_doc(self, doc):
        """
        ============================== WARNING ==============================
        This method converts the document's contents to unicode in-place. This
        means that after calling `put_doc(doc)`, the contents of the
        document, i.e. `doc.content`, might be different from before the
        call.
        ============================== WARNING ==============================
        """
        doc.content = _convert_to_unicode(doc.content)
        return self._defer("put_doc", doc)

    def delete_doc(self, doc):
        # XXX what does this do when fired???
        return self._defer("delete_doc", doc)

    def get_doc(self, doc_id, include_deleted=False):
        return self._defer(
            "get_doc", doc_id, include_deleted=include_deleted)

    def get_docs(
            self, doc_ids, check_for_conflicts=True, include_deleted=False):
        return self._defer(
            "get_docs", doc_ids, check_for_conflicts=check_for_conflicts,
            include_deleted=include_deleted)

    def get_all_docs(self, include_deleted=False):
        return self._defer("get_all_docs", include_deleted)

    def create_doc(self, content, doc_id=None):
        return self._defer(
            "create_doc", _convert_to_unicode(content), doc_id=doc_id)

    def create_doc_from_json(self, json, doc_id=None):
        return self._defer("create_doc_from_json", json, doc_id=doc_id)

    def create_index(self, index_name, *index_expressions):
        return self._defer("create_index", index_name, *index_expressions)

    def delete_index(self, index_name):
        return self._defer("delete_index", index_name)

    def list_indexes(self):
        return self._defer("list_indexes")

    def get_from_index(self, index_name, *key_values):
        return self._defer("get_from_index", index_name, *key_values)

    def get_count_from_index(self, index_name, *key_values):
        return self._defer("get_count_from_index", index_name, *key_values)

    def get_range_from_index(self, index_name, start_value, end_value):
        return self._defer(
            "get_range_from_index", index_name, start_value, end_value)

    def get_index_keys(self, index_name):
        return self._defer("get_index_keys", index_name)

    def get_doc_conflicts(self, doc_id):
        return self._defer("get_doc_conflicts", doc_id)

    def resolve_doc(self, doc, conflicted_doc_revs):
        return self._defer("resolve_doc", doc, conflicted_doc_revs)

    def _get_local_db_path(self):
        return self._local_db_path

    # XXX Do we really need all this private / property dance?

    local_db_path = property(
        _get_local_db_path,
        doc='The path for the local database replica.')

    def _get_uuid(self):
        return self._uuid

    uuid = property(_get_uuid, doc='The user uuid.')

    #
    # ISyncableStorage
    #

    def sync(self, defer_decryption=True):

        # -----------------------------------------------------------------
        # TODO this needs work.
        # Should review/write tests to check that this:

        # (1) Defer to the syncer pool -- DONE (on dbsyncer)
        # (2) Return the deferred
        # (3) Add the callback for signaling the event (executed on reactor
        #     thread)
        # (4) Check that the deferred is called with the local gen.

        # TODO document that this returns a deferred
        # -----------------------------------------------------------------

        def on_sync_done(local_gen):
            soledad_events.signal(
                soledad_events.SOLEDAD_DONE_DATA_SYNC, self.uuid)
            return local_gen

        sync_url = urlparse.urljoin(self._server_url, 'user-%s' % self.uuid)
        try:
            d = self._dbsyncer.sync(
                sync_url,
                creds=self._creds, autocreate=False,
                defer_decryption=defer_decryption)

            d.addCallbacks(on_sync_done, lambda err: log.err(err))
            return d

        # TODO catch the exception by adding an Errback
        except Exception as e:
            logger.error("Soledad exception when syncing: %s" % str(e))

    def stop_sync(self):
        self._dbsyncer.stop_sync()

    @property
    def syncing(self):
        return self._dbsyncer.syncing

    def _set_token(self, token):
        """
        Set the authentication token for remote database access.

        Internally, this builds the credentials dictionary with the following
        format:

            self._{
                'token': {
                    'uuid': '<uuid>'
                    'token': '<token>'
            }

        :param token: The authentication token.
        :type token: str
        """
        self._creds = {
            'token': {
                'uuid': self.uuid,
                'token': token,
            }
        }

    def _get_token(self):
        """
        Return current token from credentials dictionary.
        """
        return self._creds['token']['token']

    token = property(_get_token, _set_token, doc='The authentication Token.')

    #
    # ISecretsStorage
    #

    def init_shared_db(self, server_url, uuid, creds, syncable=True):
        shared_db_url = urlparse.urljoin(server_url, SHARED_DB_NAME)
        self.shared_db = SoledadSharedDatabase.open_database(
            shared_db_url,
            uuid,
            creds=creds,
            create=False,  # db should exist at this point.
            syncable=syncable)

    @property
    def storage_secret(self):
        """
        Return the secret used for symmetric encryption.
        """
        return self._secrets.storage_secret

    @property
    def remote_storage_secret(self):
        """
        Return the secret used for encryption of remotely stored data.
        """
        return self._secrets.remote_storage_secret

    @property
    def secrets(self):
        return self._secrets

    def change_passphrase(self, new_passphrase):
        self._secrets.change_passphrase(new_passphrase)


def _convert_to_unicode(content):
    """
    Convert content to unicode (or all the strings in content)

    NOTE: Even though this method supports any type, it will
    currently ignore contents of lists, tuple or any other
    iterable than dict. We don't need support for these at the
    moment

    :param content: content to convert
    :type content: object

    :rtype: object
    """
    if isinstance(content, unicode):
        return content
    elif isinstance(content, str):
        result = chardet.detect(content)
        default = "utf-8"
        encoding = result["encoding"] or default
        try:
            content = content.decode(encoding)
        except UnicodeError as e:
            logger.error("Unicode error: {0!r}. Using 'replace'".format(e))
            content = content.decode(encoding, 'replace')
        return content
    else:
        if isinstance(content, dict):
            for key in content.keys():
                content[key] = _convert_to_unicode(content[key])
    return content


def create_path_if_not_exists(path):
    try:
        if not os.path.isdir(path):
            logger.info('Creating directory: %s.' % path)
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise

# ----------------------------------------------------------------------------
# Monkey patching u1db to be able to provide a custom SSL cert
# ----------------------------------------------------------------------------

# We need a more reasonable timeout (in seconds)
SOLEDAD_TIMEOUT = 120


class VerifiedHTTPSConnection(httplib.HTTPSConnection):
    """
    HTTPSConnection verifying server side certificates.
    """
    # derived from httplib.py

    def connect(self):
        """
        Connect to a host on a given (SSL) port.
        """
        try:
            source = self.source_address
            sock = socket.create_connection((self.host, self.port),
                                            SOLEDAD_TIMEOUT, source)
        except AttributeError:
            # source_address was introduced in 2.7
            sock = socket.create_connection((self.host, self.port),
                                            SOLEDAD_TIMEOUT)
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()

        self.sock = ssl.wrap_socket(sock,
                                    ca_certs=SOLEDAD_CERT,
                                    cert_reqs=ssl.CERT_REQUIRED)
        match_hostname(self.sock.getpeercert(), self.host)


old__VerifiedHTTPSConnection = http_client._VerifiedHTTPSConnection
http_client._VerifiedHTTPSConnection = VerifiedHTTPSConnection
