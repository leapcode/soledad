# -*- coding: utf-8 -*-
# __init__.py
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

from leap.common.config import get_path_prefix
from leap.soledad.common import (
    SHARED_DB_NAME,
    soledad_assert,
    soledad_assert_type
)
from leap.soledad.client.events import (
    SOLEDAD_NEW_DATA_TO_SYNC,
    SOLEDAD_DONE_DATA_SYNC,
    signal,
)
from leap.soledad.common.document import SoledadDocument
from leap.soledad.client.crypto import SoledadCrypto
from leap.soledad.client.secrets import SoledadSecrets
from leap.soledad.client.shared_db import SoledadSharedDatabase
from leap.soledad.client.sqlcipher import open as sqlcipher_open
from leap.soledad.client.sqlcipher import SQLCipherDatabase
from leap.soledad.client.target import SoledadSyncTarget


logger = logging.getLogger(name=__name__)


#
# Constants
#

SOLEDAD_CERT = None
"""
Path to the certificate file used to certify the SSL connection between
Soledad client and server.
"""


#
# Soledad: local encrypted storage and remote encrypted sync.
#

class Soledad(object):
    """
    Soledad provides encrypted data storage and sync.

    A Soledad instance is used to store and retrieve data in a local encrypted
    database and synchronize this database with Soledad server.

    This class is also responsible for bootstrapping users' account by
    creating cryptographic secrets and/or storing/fetching them on Soledad
    server.

    Soledad uses C{leap.common.events} to signal events. The possible events
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

    LOCAL_DATABASE_FILE_NAME = 'soledad.u1db'
    """
    The name of the local SQLCipher U1DB database file.
    """

    STORAGE_SECRETS_FILE_NAME = "soledad.json"
    """
    The name of the file where the storage secrets will be stored.
    """

    DEFAULT_PREFIX = os.path.join(get_path_prefix(), 'leap', 'soledad')
    """
    Prefix for default values for path.
    """

    def __init__(self, uuid, passphrase, secrets_path, local_db_path,
                 server_url, cert_file,
                 auth_token=None, secret_id=None, defer_encryption=False):
        """
        Initialize configuration, cryptographic keys and dbs.

        :param uuid: User's uuid.
        :type uuid: str

        :param passphrase: The passphrase for locking and unlocking encryption
                           secrets for local and remote storage.
        :type passphrase: unicode

        :param secrets_path: Path for storing encrypted key used for
                             symmetric encryption.
        :type secrets_path: str

        :param local_db_path: Path for local encrypted storage db.
        :type local_db_path: str

        :param server_url: URL for Soledad server. This is used either to sync
                           with the user's remote db and to interact with the
                           shared recovery database.
        :type server_url: str

        :param cert_file: Path to the certificate of the ca used
                          to validate the SSL certificate used by the remote
                          soledad server.
        :type cert_file: str

        :param auth_token: Authorization token for accessing remote databases.
        :type auth_token: str

        :param secret_id: The id of the storage secret to be used.
        :type secret_id: str

        :param defer_encryption: Whether to defer encryption/decryption of
                                 documents, or do it inline while syncing.
        :type defer_encryption: bool

        :raise BootstrapSequenceError: Raised when the secret generation and
                                       storage on server sequence has failed
                                       for some reason.
        """
        # store config params
        self._uuid = uuid
        self._passphrase = passphrase
        self._secrets_path = secrets_path
        self._local_db_path = local_db_path
        self._server_url = server_url
        # configure SSL certificate
        global SOLEDAD_CERT
        SOLEDAD_CERT = cert_file
        self._set_token(auth_token)
        self._defer_encryption = defer_encryption

        self._init_config()
        self._init_dirs()

        # init crypto variables
        self._shared_db_instance = None
        self._crypto = SoledadCrypto(self)
        self._secrets = SoledadSecrets(
            self._uuid,
            self._passphrase,
            self._secrets_path,
            self._shared_db,
            self._crypto,
            secret_id=secret_id)

        # initiate bootstrap sequence
        self._bootstrap()  # might raise BootstrapSequenceError()

    def _init_config(self):
        """
        Initialize configuration using default values for missing params.
        """
        soledad_assert_type(self._passphrase, unicode)
        # initialize secrets_path
        if self._secrets_path is None:
            self._secrets_path = os.path.join(
                self.DEFAULT_PREFIX, self.STORAGE_SECRETS_FILE_NAME)
        # initialize local_db_path
        if self._local_db_path is None:
            self._local_db_path = os.path.join(
                self.DEFAULT_PREFIX, self.LOCAL_DATABASE_FILE_NAME)
        # initialize server_url
        soledad_assert(
            self._server_url is not None,
            'Missing URL for Soledad server.')

    #
    # initialization/destruction methods
    #

    def _bootstrap(self):
        """
        Bootstrap local Soledad instance.

        :raise BootstrapSequenceError: Raised when the secret generation and
            storage on server sequence has failed for some reason.
        """
        try:
            self._secrets.bootstrap()
            self._init_db()
        except:
            raise

    def _init_dirs(self):
        """
        Create work directories.

        :raise OSError: in case file exists and is not a dir.
        """
        paths = map(
            lambda x: os.path.dirname(x),
            [self._local_db_path, self._secrets_path])
        for path in paths:
            try:
                if not os.path.isdir(path):
                    logger.info('Creating directory: %s.' % path)
                os.makedirs(path)
            except OSError as exc:
                if exc.errno == errno.EEXIST and os.path.isdir(path):
                    pass
                else:
                    raise

    def _init_db(self):
        """
        Initialize the U1DB SQLCipher database for local storage.

        Currently, Soledad uses the default SQLCipher cipher, i.e.
        'aes-256-cbc'. We use scrypt to derive a 256-bit encryption key and
        uses the 'raw PRAGMA key' format to handle the key to SQLCipher.
        """
        key = self._secrets.get_local_storage_key()
        sync_db_key = self._secrets.get_sync_db_key()
        self._db = sqlcipher_open(
            self._local_db_path,
            binascii.b2a_hex(key),  # sqlcipher only accepts the hex version
            create=True,
            document_factory=SoledadDocument,
            crypto=self._crypto,
            raw_key=True,
            defer_encryption=self._defer_encryption,
            sync_db_key=binascii.b2a_hex(sync_db_key))

    def close(self):
        """
        Close underlying U1DB database.
        """
        logger.debug("Closing soledad")
        if hasattr(self, '_db') and isinstance(
                self._db,
                SQLCipherDatabase):
            self._db.stop_sync()
            self._db.close()

    @property
    def _shared_db(self):
        """
        Return an instance of the shared recovery database object.

        :return: The shared database.
        :rtype: SoledadSharedDatabase
        """
        if self._shared_db_instance is None:
            self._shared_db_instance = SoledadSharedDatabase.open_database(
                urlparse.urljoin(self.server_url, SHARED_DB_NAME),
                self._uuid,
                False,  # db should exist at this point.
                creds=self._creds)
        return self._shared_db_instance

    #
    # Document storage, retrieval and sync.
    #

    def put_doc(self, doc):
        """
        Update a document in the local encrypted database.

        ============================== WARNING ==============================
        This method converts the document's contents to unicode in-place. This
        means that after calling C{put_doc(doc)}, the contents of the
        document, i.e. C{doc.content}, might be different from before the
        call.
        ============================== WARNING ==============================

        :param doc: the document to update
        :type doc: SoledadDocument

        :return: the new revision identifier for the document
        :rtype: str
        """
        doc.content = self._convert_to_unicode(doc.content)
        return self._db.put_doc(doc)

    def delete_doc(self, doc):
        """
        Delete a document from the local encrypted database.

        :param doc: the document to delete
        :type doc: SoledadDocument

        :return: the new revision identifier for the document
        :rtype: str
        """
        return self._db.delete_doc(doc)

    def get_doc(self, doc_id, include_deleted=False):
        """
        Retrieve a document from the local encrypted database.

        :param doc_id: the unique document identifier
        :type doc_id: str
        :param include_deleted: if True, deleted documents will be
                                returned with empty content; otherwise asking
                                for a deleted document will return None
        :type include_deleted: bool

        :return: the document object or None
        :rtype: SoledadDocument
        """
        return self._db.get_doc(doc_id, include_deleted=include_deleted)

    def get_docs(self, doc_ids, check_for_conflicts=True,
                 include_deleted=False):
        """
        Get the content for many documents.

        :param doc_ids: a list of document identifiers
        :type doc_ids: list
        :param check_for_conflicts: if set False, then the conflict check will
            be skipped, and 'None' will be returned instead of True/False
        :type check_for_conflicts: bool

        :return: iterable giving the Document object for each document id
            in matching doc_ids order.
        :rtype: generator
        """
        return self._db.get_docs(
            doc_ids, check_for_conflicts=check_for_conflicts,
            include_deleted=include_deleted)

    def get_all_docs(self, include_deleted=False):
        """
        Get the JSON content for all documents in the database.

        :param include_deleted: If set to True, deleted documents will be
                                returned with empty content. Otherwise deleted
                                documents will not be included in the results.
        :return: (generation, [Document])
                 The current generation of the database, followed by a list of
                 all the documents in the database.
        """
        return self._db.get_all_docs(include_deleted)

    def _convert_to_unicode(self, content):
        """
        Converts content to unicode (or all the strings in content)

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
                    content[key] = self._convert_to_unicode(content[key])
        return content

    def create_doc(self, content, doc_id=None):
        """
        Create a new document in the local encrypted database.

        :param content: the contents of the new document
        :type content: dict
        :param doc_id: an optional identifier specifying the document id
        :type doc_id: str

        :return: the new document
        :rtype: SoledadDocument
        """
        return self._db.create_doc(
            self._convert_to_unicode(content), doc_id=doc_id)

    def create_doc_from_json(self, json, doc_id=None):
        """
        Create a new document.

        You can optionally specify the document identifier, but the document
        must not already exist. See 'put_doc' if you want to override an
        existing document.
        If the database specifies a maximum document size and the document
        exceeds it, create will fail and raise a DocumentTooBig exception.

        :param json: The JSON document string
        :type json: str
        :param doc_id: An optional identifier specifying the document id.
        :type doc_id:
        :return: The new document
        :rtype: SoledadDocument
        """
        return self._db.create_doc_from_json(json, doc_id=doc_id)

    def create_index(self, index_name, *index_expressions):
        """
        Create an named index, which can then be queried for future lookups.
        Creating an index which already exists is not an error, and is cheap.
        Creating an index which does not match the index_expressions of the
        existing index is an error.
        Creating an index will block until the expressions have been evaluated
        and the index generated.

        :param index_name: A unique name which can be used as a key prefix
        :type index_name: str
        :param index_expressions: index expressions defining the index
                                  information.
        :type index_expressions: dict

            Examples:

            "fieldname", or "fieldname.subfieldname" to index alphabetically
            sorted on the contents of a field.

            "number(fieldname, width)", "lower(fieldname)"
        """
        if self._db:
            return self._db.create_index(
                index_name, *index_expressions)

    def delete_index(self, index_name):
        """
        Remove a named index.

        :param index_name: The name of the index we are removing
        :type index_name: str
        """
        if self._db:
            return self._db.delete_index(index_name)

    def list_indexes(self):
        """
        List the definitions of all known indexes.

        :return: A list of [('index-name', ['field', 'field2'])] definitions.
        :rtype: list
        """
        if self._db:
            return self._db.list_indexes()

    def get_from_index(self, index_name, *key_values):
        """
        Return documents that match the keys supplied.

        You must supply exactly the same number of values as have been defined
        in the index. It is possible to do a prefix match by using '*' to
        indicate a wildcard match. You can only supply '*' to trailing entries,
        (eg 'val', '*', '*' is allowed, but '*', 'val', 'val' is not.)
        It is also possible to append a '*' to the last supplied value (eg
        'val*', '*', '*' or 'val', 'val*', '*', but not 'val*', 'val', '*')

        :param index_name: The index to query
        :type index_name: str
        :param key_values: values to match. eg, if you have
                           an index with 3 fields then you would have:
                           get_from_index(index_name, val1, val2, val3)
        :type key_values: tuple
        :return: List of [Document]
        :rtype: list
        """
        if self._db:
            return self._db.get_from_index(index_name, *key_values)

    def get_count_from_index(self, index_name, *key_values):
        """
        Return the count of the documents that match the keys and
        values supplied.

        :param index_name: The index to query
        :type index_name: str
        :param key_values: values to match. eg, if you have
                           an index with 3 fields then you would have:
                           get_from_index(index_name, val1, val2, val3)
        :type key_values: tuple
        :return: count.
        :rtype: int
        """
        if self._db:
            return self._db.get_count_from_index(index_name, *key_values)

    def get_range_from_index(self, index_name, start_value, end_value):
        """
        Return documents that fall within the specified range.

        Both ends of the range are inclusive. For both start_value and
        end_value, one must supply exactly the same number of values as have
        been defined in the index, or pass None. In case of a single column
        index, a string is accepted as an alternative for a tuple with a single
        value. It is possible to do a prefix match by using '*' to indicate
        a wildcard match. You can only supply '*' to trailing entries, (eg
        'val', '*', '*' is allowed, but '*', 'val', 'val' is not.) It is also
        possible to append a '*' to the last supplied value (eg 'val*', '*',
        '*' or 'val', 'val*', '*', but not 'val*', 'val', '*')

        :param index_name: The index to query
        :type index_name: str
        :param start_values: tuples of values that define the lower bound of
            the range. eg, if you have an index with 3 fields then you would
            have: (val1, val2, val3)
        :type start_values: tuple
        :param end_values: tuples of values that define the upper bound of the
            range. eg, if you have an index with 3 fields then you would have:
            (val1, val2, val3)
        :type end_values: tuple
        :return: List of [Document]
        :rtype: list
        """
        if self._db:
            return self._db.get_range_from_index(
                index_name, start_value, end_value)

    def get_index_keys(self, index_name):
        """
        Return all keys under which documents are indexed in this index.

        :param index_name: The index to query
        :type index_name: str
        :return: [] A list of tuples of indexed keys.
        :rtype: list
        """
        if self._db:
            return self._db.get_index_keys(index_name)

    def get_doc_conflicts(self, doc_id):
        """
        Get the list of conflicts for the given document.

        :param doc_id: the document id
        :type doc_id: str

        :return: a list of the document entries that are conflicted
        :rtype: list
        """
        if self._db:
            return self._db.get_doc_conflicts(doc_id)

    def resolve_doc(self, doc, conflicted_doc_revs):
        """
        Mark a document as no longer conflicted.

        :param doc: a document with the new content to be inserted.
        :type doc: SoledadDocument
        :param conflicted_doc_revs: a list of revisions that the new content
                                    supersedes.
        :type conflicted_doc_revs: list
        """
        if self._db:
            return self._db.resolve_doc(doc, conflicted_doc_revs)

    def sync(self, defer_decryption=True):
        """
        Synchronize the local encrypted replica with a remote replica.

        This method blocks until a syncing lock is acquired, so there are no
        attempts of concurrent syncs from the same client replica.

        :param url: the url of the target replica to sync with
        :type url: str

        :param defer_decryption: Whether to defer the decryption process using
                                 the intermediate database. If False,
                                 decryption will be done inline.
        :type defer_decryption: bool

        :return: The local generation before the synchronisation was
                 performed.
        :rtype: str
        """
        if self._db:
            try:
                local_gen = self._db.sync(
                    urlparse.urljoin(self.server_url, 'user-%s' % self._uuid),
                    creds=self._creds, autocreate=False,
                    defer_decryption=defer_decryption)
                signal(SOLEDAD_DONE_DATA_SYNC, self._uuid)
                return local_gen
            except Exception as e:
                logger.error("Soledad exception when syncing: %s" % str(e))

    def stop_sync(self):
        """
        Stop the current syncing process.
        """
        if self._db:
            self._db.stop_sync()

    def need_sync(self, url):
        """
        Return if local db replica differs from remote url's replica.

        :param url: The remote replica to compare with local replica.
        :type url: str

        :return: Whether remote replica and local replica differ.
        :rtype: bool
        """
        target = SoledadSyncTarget(
            url, self._db._get_replica_uid(), creds=self._creds,
            crypto=self._crypto)
        info = target.get_sync_info(self._db._get_replica_uid())
        # compare source generation with target's last known source generation
        if self._db._get_generation() != info[4]:
            signal(SOLEDAD_NEW_DATA_TO_SYNC, self._uuid)
            return True
        return False

    @property
    def syncing(self):
        """
        Property, True if the syncer is syncing.
        """
        return self._db.syncing

    def _set_token(self, token):
        """
        Set the authentication token for remote database access.

        Build the credentials dictionary with the following format:

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
                'uuid': self._uuid,
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
    # Setters/getters
    #

    def _get_uuid(self):
        return self._uuid

    uuid = property(_get_uuid, doc='The user uuid.')

    def get_secret_id(self):
        return self._secrets.secret_id

    def set_secret_id(self, secret_id):
        self._secrets.set_secret_id(secret_id)

    secret_id = property(
        get_secret_id,
        set_secret_id,
        doc='The active secret id.')

    def _set_secrets_path(self, secrets_path):
        self._secrets.secrets_path = secrets_path

    def _get_secrets_path(self):
        return self._secrets.secrets_path

    secrets_path = property(
        _get_secrets_path,
        _set_secrets_path,
        doc='The path for the file containing the encrypted symmetric secret.')

    def _get_local_db_path(self):
        return self._local_db_path

    local_db_path = property(
        _get_local_db_path,
        doc='The path for the local database replica.')

    def _get_server_url(self):
        return self._server_url

    server_url = property(
        _get_server_url,
        doc='The URL of the Soledad server.')

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

    @property
    def passphrase(self):
        return self._secrets.passphrase

    def change_passphrase(self, new_passphrase):
        """
        Change the passphrase that encrypts the storage secret.

        :param new_passphrase: The new passphrase.
        :type new_passphrase: unicode

        :raise NoStorageSecret: Raised if there's no storage secret available.
        """
        self._secrets.change_passphrase(new_passphrase)


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

        highest_supported = ssl.PROTOCOL_SSLv23

        try:
            # needs python 2.7.9+
            # negotiate the best available version,
            # but explicitely disabled bad ones.
            ctx = ssl.SSLContext(highest_supported)
            ctx.options |= ssl.OP_NO_SSLv2
            ctx.options |= ssl.OP_NO_SSLv3

            ctx.load_verify_locations(cafile=SOLEDAD_CERT)
            ctx.verify_mode = ssl.CERT_REQUIRED
            self.sock = ctx.wrap_socket(sock)

        except AttributeError:
            self.sock = ssl.wrap_socket(
                sock, ca_certs=SOLEDAD_CERT, cert_reqs=ssl.CERT_REQUIRED,
                ssl_version=highest_supported)

        match_hostname(self.sock.getpeercert(), self.host)


old__VerifiedHTTPSConnection = http_client._VerifiedHTTPSConnection
http_client._VerifiedHTTPSConnection = VerifiedHTTPSConnection


__all__ = ['soledad_assert', 'Soledad']

from ._version import get_versions
__version__ = get_versions()['version']
del get_versions
