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
import os
import socket
import ssl
import uuid

from itertools import chain
import six.moves.http_client as httplib
import six.moves.urllib.parse as urlparse
from six import StringIO
from collections import defaultdict

from twisted.internet import defer
from zope.interface import implementer

from leap.common.config import get_path_prefix
from leap.common.plugins import collect_plugins

from leap.soledad.common import soledad_assert
from leap.soledad.common import soledad_assert_type
from leap.soledad.common.log import getLogger
from leap.soledad.common.l2db.remote import http_client
from leap.soledad.common.l2db.remote.ssl_match_hostname import match_hostname
from leap.soledad.common.errors import DatabaseAccessError

from . import events as soledad_events
from . import interfaces as soledad_interfaces
from ._crypto import SoledadCrypto
from ._db import adbapi
from ._db import blobs
from ._db import sqlcipher
from ._recovery_code import RecoveryCode
from ._secrets import Secrets


logger = getLogger(__name__)


# we may want to collect statistics from the sync process
DO_STATS = False
if os.environ.get('SOLEDAD_STATS'):
    DO_STATS = True


#
# Constants
#

"""
Path to the certificate file used to certify the SSL connection between
Soledad client and server.
"""
SOLEDAD_CERT = None


@implementer(soledad_interfaces.ILocalStorage,
             soledad_interfaces.ISyncableStorage,
             soledad_interfaces.ISecretsStorage)
class Soledad(object):
    """
    Soledad provides encrypted data storage and sync.

    A Soledad instance is used to store and retrieve data in a local encrypted
    database and synchronize this database with Soledad server.

    This class is also responsible for bootstrapping users' account by
    creating cryptographic secrets and/or storing/fetching them on Soledad
    server.
    """

    local_db_file_name = 'soledad.u1db'
    secrets_file_name = "soledad.json"
    default_prefix = os.path.join(get_path_prefix(), 'leap', 'soledad')

    """
    A dictionary that holds locks which avoid multiple sync attempts from the
    same database replica. The dictionary indexes are the paths to each local
    db, so we guarantee that only one sync happens for a local db at a time.
    """
    _sync_lock = defaultdict(defer.DeferredLock)

    def __init__(self, uuid, passphrase, secrets_path, local_db_path,
                 server_url, cert_file, shared_db=None,
                 auth_token=None, with_blobs=False):
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
            URL for Soledad server. This is used to fetch and store user's
            secrets and to sync with the user's remote db.

            For the LEAP Platform/Bitmask use case, it is mandatory to check
            for user secrets previously stored in remote storage during the
            first initialization, because Soledad needs to encrypt/decrypt to
            using the same secret as before.

            For testing purposes, a value of None can be passed. If None is
            passed, verification for a remote secret on first initialization is
            bypassed and that might lead to unintented consequences.
        :type server_url: str

        :param cert_file:
            Path to the certificate of the ca used to validate the SSL
            certificate used by the remote soledad server.
        :type cert_file: str

        :param shared_db:
            The shared database.
        :type shared_db: HTTPDatabase

        :param auth_token:
            Authorization token for accessing remote databases.
        :type auth_token: str

        :param with_blobs:
            A boolean that specifies if this soledad instance should enable
            blobs storage when initialized. This will raise if it's not the
            first initialization and the passed value is different from when
            the database was first initialized.

        :raise BootstrapSequenceError:
            Raised when the secret initialization sequence (i.e. retrieval
            from server or generation and storage on server) has failed for
            some reason.
        """
        # store config params
        self.uuid = uuid
        self.passphrase = passphrase
        self.secrets_path = secrets_path
        self._local_db_path = local_db_path
        self.server_url = server_url
        self.shared_db = shared_db
        self.token = auth_token

        self._dbsyncer = None

        # configure SSL certificate
        global SOLEDAD_CERT
        SOLEDAD_CERT = cert_file

        self._init_config_with_defaults()
        self._init_working_dirs()

        self._recovery_code = RecoveryCode()
        self._secrets = Secrets(self)
        self._crypto = SoledadCrypto(self._secrets.remote_secret)

        try:
            # initialize database access, trap any problems so we can shutdown
            # smoothly.
            self._init_u1db_sqlcipher_backend()
            self._init_u1db_syncer()
        except DatabaseAccessError:
            # oops! something went wrong with backend initialization. We
            # have to close any thread-related stuff we have already opened
            # here, otherwise there might be zombie threads that may clog the
            # reactor.
            if hasattr(self, '_dbpool'):
                self._dbpool.close()
            raise

        if with_blobs:
            self._init_blobmanager()
        else:
            self.blobmanager = None

    #
    # initialization/destruction methods
    #

    def _init_config_with_defaults(self):
        """
        Initialize configuration using default values for missing params.
        """
        soledad_assert_type(self.passphrase, unicode)

        def initialize(attr, val):
            return ((getattr(self, attr, None) is None) and
                    setattr(self, attr, val))

        initialize("_secrets_path", os.path.join(
            self.default_prefix, self.secrets_file_name))
        initialize("_local_db_path", os.path.join(
            self.default_prefix, self.local_db_file_name))

    def _init_working_dirs(self):
        """
        Create work directories.

        :raise OSError: in case file exists and is not a dir.
        """
        paths = map(lambda x: os.path.dirname(x), [
            self._local_db_path, self._secrets_path])
        for path in paths:
            create_path_if_not_exists(path)

    def _init_u1db_sqlcipher_backend(self):
        """
        Initialize the U1DB SQLCipher database for local storage.

        Instantiates a modified twisted adbapi that will maintain a threadpool
        with a u1db-sqclipher connection for each thread, and will return
        deferreds for each u1db query.

        Currently, Soledad uses the default SQLCipher cipher, i.e.
        'aes-256-cbc'. We use scrypt to derive a 256-bit encryption key,
        and internally the SQLCipherDatabase initialization uses the 'raw
        PRAGMA key' format to handle the key to SQLCipher.
        """
        tohex = binascii.b2a_hex
        # sqlcipher only accepts the hex version
        key = tohex(self._secrets.local_key)

        opts = sqlcipher.SQLCipherOptions(
            self._local_db_path, key,
            is_raw_key=True, create=True)
        self._sqlcipher_opts = opts
        self._dbpool = adbapi.getConnectionPool(opts)

    def _init_u1db_syncer(self):
        """
        Initialize the U1DB synchronizer.
        """
        replica_uid = self._dbpool.replica_uid
        self._dbsyncer = sqlcipher.SQLCipherU1DBSync(
            self._sqlcipher_opts, self._crypto, replica_uid,
            SOLEDAD_CERT)

    def sync_stats(self):
        sync_phase = 0
        if getattr(self._dbsyncer, 'sync_phase', None):
            sync_phase = self._dbsyncer.sync_phase[0]
        sync_exchange_phase = 0
        if getattr(self._dbsyncer, 'syncer', None):
            if getattr(self._dbsyncer.syncer, 'sync_exchange_phase', None):
                _p = self._dbsyncer.syncer.sync_exchange_phase[0]
                sync_exchange_phase = _p
        return sync_phase, sync_exchange_phase

    def _init_blobmanager(self):
        path = os.path.dirname(self._local_db_path)
        if not self.server_url:
            return
        url = urlparse.urljoin(self.server_url, 'blobs/%s' % self.uuid)
        key = self._secrets.local_key
        self.blobmanager = blobs.BlobManager(
            path, url, key, self._secrets.remote_secret,
            self.uuid, self.token, SOLEDAD_CERT)

    #
    # Closing methods
    #

    def close(self):
        """
        Close underlying U1DB database.
        """
        logger.debug("closing soledad")
        self._dbpool.close()
        if self.blobmanager:
            self.blobmanager.close()
        if getattr(self, '_dbsyncer', None):
            self._dbsyncer.close()

    #
    # ILocalStorage
    #

    def _defer(self, meth, *args, **kw):
        """
        Defer a method to be run on a U1DB connection pool.

        :param meth: A method to defer to the U1DB connection pool.
        :type meth: callable
        :return: A deferred.
        :rtype: twisted.internet.defer.Deferred
        """
        return self._dbpool.runU1DBQuery(meth, *args, **kw)

    def put_doc(self, doc):
        """
        Update a document.

        If the document currently has conflicts, put will fail.
        If the database specifies a maximum document size and the document
        exceeds it, put will fail and raise a DocumentTooBig exception.

        ============================== WARNING ==============================
        This method converts the document's contents to unicode in-place. This
        means that after calling `put_doc(doc)`, the contents of the
        document, i.e. `doc.content`, might be different from before the
        call.
        ============================== WARNING ==============================

        :param doc: A document with new content.
        :type doc: leap.soledad.common.document.Document
        :return: A deferred whose callback will be invoked with the new
            revision identifier for the document. The document object will
            also be updated.
        :rtype: twisted.internet.defer.Deferred
        """
        d = self._defer("put_doc", doc)
        return d

    def delete_doc(self, doc):
        """
        Mark a document as deleted.

        Will abort if the current revision doesn't match doc.rev.
        This will also set doc.content to None.

        :param doc: A document to be deleted.
        :type doc: leap.soledad.common.document.Document
        :return: A deferred.
        :rtype: twisted.internet.defer.Deferred
        """
        soledad_assert(doc is not None, "delete_doc doesn't accept None.")
        return self._defer("delete_doc", doc)

    def get_doc(self, doc_id, include_deleted=False):
        """
        Get the JSON string for the given document.

        :param doc_id: The unique document identifier
        :type doc_id: str
        :param include_deleted: If set to True, deleted documents will be
            returned with empty content. Otherwise asking for a deleted
            document will return None.
        :type include_deleted: bool
        :return: A deferred whose callback will be invoked with a document
            object.
        :rtype: twisted.internet.defer.Deferred
        """
        return self._defer(
            "get_doc", doc_id, include_deleted=include_deleted)

    def get_docs(
            self, doc_ids, check_for_conflicts=True, include_deleted=False):
        """
        Get the JSON content for many documents.

        :param doc_ids: A list of document identifiers.
        :type doc_ids: list
        :param check_for_conflicts: If set to False, then the conflict check
            will be skipped, and 'None' will be returned instead of True/False.
        :type check_for_conflicts: bool
        :param include_deleted: If set to True, deleted documents will be
            returned with empty content. Otherwise deleted documents will not
            be included in the results.
        :type include_deleted: bool
        :return: A deferred whose callback will be invoked with an iterable
            giving the document object for each document id in matching
            doc_ids order.
        :rtype: twisted.internet.defer.Deferred
        """
        return self._defer(
            "get_docs", doc_ids, check_for_conflicts=check_for_conflicts,
            include_deleted=include_deleted)

    def get_all_docs(self, include_deleted=False):
        """
        Get the JSON content for all documents in the database.

        :param include_deleted: If set to True, deleted documents will be
            returned with empty content. Otherwise deleted documents will not
            be included in the results.
        :type include_deleted: bool

        :return: A deferred which, when fired, will pass the a tuple
            containing (generation, [Document]) to the callback, with the
            current generation of the database, followed by a list of all the
            documents in the database.
        :rtype: twisted.internet.defer.Deferred
        """
        return self._defer("get_all_docs", include_deleted)

    @defer.inlineCallbacks
    def create_doc(self, content, doc_id=None):
        """
        Create a new document.

        You can optionally specify the document identifier, but the document
        must not already exist. See 'put_doc' if you want to override an
        existing document.
        If the database specifies a maximum document size and the document
        exceeds it, create will fail and raise a DocumentTooBig exception.

        :param content: A Python dictionary.
        :type content: dict
        :param doc_id: An optional identifier specifying the document id.
        :type doc_id: str
        :return: A deferred whose callback will be invoked with a document.
        :rtype: twisted.internet.defer.Deferred
        """
        # TODO we probably should pass an optional "encoding" parameter to
        # create_doc (and probably to put_doc too). There are cases (mail
        # payloads for example) in which we already have the encoding in the
        # headers, so we don't need to guess it.
        doc = yield self._defer("create_doc", content, doc_id=doc_id)
        doc.set_store(self)
        defer.returnValue(doc)

    def create_doc_from_json(self, json, doc_id=None):
        """
        Create a new document.

        You can optionally specify the document identifier, but the document
        must not already exist. See 'put_doc' if you want to override an
        existing document.
        If the database specifies a maximum document size and the document
        exceeds it, create will fail and raise a DocumentTooBig exception.

        :param json: The JSON document string
        :type json: dict
        :param doc_id: An optional identifier specifying the document id.
        :type doc_id: str
        :return: A deferred whose callback will be invoked with a document.
        :rtype: twisted.internet.defer.Deferred
        """
        return self._defer("create_doc_from_json", json, doc_id=doc_id)

    def create_index(self, index_name, *index_expressions):
        """
        Create a named index, which can then be queried for future lookups.

        Creating an index which already exists is not an error, and is cheap.
        Creating an index which does not match the index_expressions of the
        existing index is an error.
        Creating an index will block until the expressions have been evaluated
        and the index generated.

        :param index_name: A unique name which can be used as a key prefix
        :type index_name: str
        :param index_expressions: index expressions defining the index
            information.

            Examples:

            "fieldname", or "fieldname.subfieldname" to index alphabetically
            sorted on the contents of a field.

            "number(fieldname, width)", "lower(fieldname)"
        :type index_expresions: list of str
        :return: A deferred.
        :rtype: twisted.internet.defer.Deferred
        """
        return self._defer("create_index", index_name, *index_expressions)

    def delete_index(self, index_name):
        """
        Remove a named index.

        :param index_name: The name of the index we are removing
        :type index_name: str
        :return: A deferred.
        :rtype: twisted.internet.defer.Deferred
        """
        return self._defer("delete_index", index_name)

    def list_indexes(self):
        """
        List the definitions of all known indexes.

        :return: A deferred whose callback will be invoked with a list of
            [('index-name', ['field', 'field2'])] definitions.
        :rtype: twisted.internet.defer.Deferred
        """
        return self._defer("list_indexes")

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
        :type key_values: list
        :return: A deferred whose callback will be invoked with a list of
            [Document].
        :rtype: twisted.internet.defer.Deferred
        """
        return self._defer("get_from_index", index_name, *key_values)

    def get_count_from_index(self, index_name, *key_values):
        """
        Return the count for a given combination of index_name
        and key values.

        Extension method made from similar methods in u1db version 13.09

        :param index_name: The index to query
        :type index_name: str
        :param key_values: values to match. eg, if you have
                           an index with 3 fields then you would have:
                           get_from_index(index_name, val1, val2, val3)
        :type key_values: tuple
        :return: A deferred whose callback will be invoked with the count.
        :rtype: twisted.internet.defer.Deferred
        """
        return self._defer("get_count_from_index", index_name, *key_values)

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
        :return: A deferred whose callback will be invoked with a list of
            [Document].
        :rtype: twisted.internet.defer.Deferred
        """

        return self._defer(
            "get_range_from_index", index_name, start_value, end_value)

    def get_index_keys(self, index_name):
        """
        Return all keys under which documents are indexed in this index.

        :param index_name: The index to query
        :type index_name: str
        :return: A deferred whose callback will be invoked with a list of
            tuples of indexed keys.
        :rtype: twisted.internet.defer.Deferred
        """
        return self._defer("get_index_keys", index_name)

    def get_doc_conflicts(self, doc_id):
        """
        Get the list of conflicts for the given document.

        The order of the conflicts is such that the first entry is the value
        that would be returned by "get_doc".

        :param doc_id: The unique document identifier
        :type doc_id: str
        :return: A deferred whose callback will be invoked with a list of the
            Document entries that are conflicted.
        :rtype: twisted.internet.defer.Deferred
        """
        return self._defer("get_doc_conflicts", doc_id)

    def resolve_doc(self, doc, conflicted_doc_revs):
        """
        Mark a document as no longer conflicted.

        We take the list of revisions that the client knows about that it is
        superseding. This may be a different list from the actual current
        conflicts, in which case only those are removed as conflicted.  This
        may fail if the conflict list is significantly different from the
        supplied information. (sync could have happened in the background from
        the time you GET_DOC_CONFLICTS until the point where you RESOLVE)

        :param doc: A Document with the new content to be inserted.
        :type doc: Document
        :param conflicted_doc_revs: A list of revisions that the new content
            supersedes.
        :type conflicted_doc_revs: list(str)
        :return: A deferred.
        :rtype: twisted.internet.defer.Deferred
        """
        return self._defer("resolve_doc", doc, conflicted_doc_revs)

    @property
    def local_db_path(self):
        return self._local_db_path

    @property
    def userid(self):
        return self.uuid

    #
    # ISyncableStorage
    #

    def sync(self):
        """
        Synchronize documents with the server replica.

        This method uses a lock to prevent multiple concurrent sync processes
        over the same local db file.

        :return: A deferred lock that will run the actual sync process when
                 the lock is acquired, and which will fire with with the local
                 generation before the synchronization was performed.
        :rtype: twisted.internet.defer.Deferred
        """
        # maybe bypass sync
        # TODO: That's because bitmask may not provide us a token, but
        # this should be handled on the caller side. Here, calling us without
        # a token is a real error.
        if not self.token:
            generation = self._dbsyncer.get_generation()
            return defer.succeed(generation)

        d = self.sync_lock.run(
            self._sync)
        return d

    def _sync(self):
        """
        Synchronize documents with the server replica.

        :return: A deferred whose callback will be invoked with the local
            generation before the synchronization was performed.
        :rtype: twisted.internet.defer.Deferred
        """
        if not self.server_url:
            return
        sync_url = urlparse.urljoin(self.server_url, 'user-%s' % self.uuid)
        if not self._dbsyncer:
            return
        creds = {'token': {'uuid': self.uuid, 'token': self.token}}
        d = self._dbsyncer.sync(sync_url, creds=creds)

        def _sync_callback(local_gen):
            self._last_received_docs = docs = self._dbsyncer.received_docs

            # Post-Sync Hooks
            if docs:
                iface = soledad_interfaces.ISoledadPostSyncPlugin
                suitable_plugins = collect_plugins(iface)
                for plugin in suitable_plugins:
                    watched = plugin.watched_doc_types
                    r = [filter(
                        lambda s: s.startswith(preffix),
                        docs) for preffix in watched]
                    filtered = list(chain(*r))
                    plugin.process_received_docs(filtered)

            return local_gen

        def _sync_errback(failure):
            s = StringIO()
            failure.printDetailedTraceback(file=s)
            msg = "got exception when syncing!\n" + s.getvalue()
            logger.error(msg)
            return failure

        def _emit_done_data_sync(passthrough):
            user_data = {'uuid': self.uuid, 'userid': self.userid}
            soledad_events.emit_async(
                soledad_events.SOLEDAD_DONE_DATA_SYNC, user_data)
            return passthrough

        d.addCallbacks(_sync_callback, _sync_errback)
        d.addCallback(_emit_done_data_sync)
        return d

    @property
    def sync_lock(self):
        """
        Class based lock to prevent concurrent syncs using the same local db
        file.

        :return: A shared lock based on this instance's db file path.
        :rtype: DeferredLock
        """
        return self._sync_lock[self._local_db_path]

    @property
    def syncing(self):
        """
        Return wether Soledad is currently synchronizing with the server.

        :return: Wether Soledad is currently synchronizing with the server.
        :rtype: bool
        """
        return self.sync_lock.locked

    #
    # ISecretsStorage
    #

    @property
    def secrets(self):
        """
        Return the secrets object.

        :return: The secrets object.
        :rtype: Secrets
        """
        return self._secrets

    def change_passphrase(self, new_passphrase):
        """
        Change the passphrase that encrypts the storage secret.

        :param new_passphrase: The new passphrase.
        :type new_passphrase: unicode

        :raise NoStorageSecret: Raised if there's no storage secret available.
        """
        self.passphrase = new_passphrase
        self._secrets.store_secrets()

    #
    # Raw SQLCIPHER Queries
    #

    def raw_sqlcipher_query(self, *args, **kw):
        """
        Run a raw sqlcipher query in the local database, and return a deferred
        that will be fired with the result.
        """
        return self._dbpool.runQuery(*args, **kw)

    def raw_sqlcipher_operation(self, *args, **kw):
        """
        Run a raw sqlcipher operation in the local database, and return a
        deferred that will be fired with None.
        """
        return self._dbpool.runOperation(*args, **kw)

    #
    # Service authentication
    #

    @defer.inlineCallbacks
    def get_or_create_service_token(self, service):
        """
        Return the stored token for a given service, or generates and stores a
        random one if it does not exist.

        These tokens can be used to authenticate services.
        """
        # FIXME this could use the local sqlcipher database, to avoid
        # problems with different replicas creating different tokens.

        yield self.create_index('by-servicetoken', 'type', 'service')
        docs = yield self._get_token_for_service(service)
        if docs:
            doc = docs[0]
            defer.returnValue(doc.content['token'])
        else:
            token = str(uuid.uuid4()).replace('-', '')[-24:]
            yield self._set_token_for_service(service, token)
            defer.returnValue(token)

    def _get_token_for_service(self, service):
        return self.get_from_index('by-servicetoken', 'servicetoken', service)

    def _set_token_for_service(self, service, token):
        doc = {'type': 'servicetoken', 'service': service, 'token': token}
        return self.create_doc(doc)

    def create_recovery_code(self):
        return self._recovery_code.generate()


def create_path_if_not_exists(path):
    try:
        if not os.path.isdir(path):
            logger.info('creating directory: %s.' % path)
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
