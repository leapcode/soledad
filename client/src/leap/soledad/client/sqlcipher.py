# -*- coding: utf-8 -*-
# sqlcipher.py
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
A U1DB backend that uses SQLCipher as its persistence layer.

The SQLCipher API (http://sqlcipher.net/sqlcipher-api/) is fully implemented,
with the exception of the following statements:

  * PRAGMA cipher_use_hmac
  * PRAGMA cipher_default_use_mac

SQLCipher 2.0 introduced a per-page HMAC to validate that the page data has
not be tampered with. By default, when creating or opening a database using
SQLCipher 2, SQLCipher will attempt to use an HMAC check. This change in
database format means that SQLCipher 2 can't operate on version 1.1.x
databases by default. Thus, in order to provide backward compatibility with
SQLCipher 1.1.x, PRAGMA cipher_use_hmac can be used to disable the HMAC
functionality on specific databases.

In some very specific cases, it is not possible to call PRAGMA cipher_use_hmac
as one of the first operations on a database. An example of this is when
trying to ATTACH a 1.1.x database to the main database. In these cases PRAGMA
cipher_default_use_hmac can be used to globally alter the default use of HMAC
when opening a database.

So, as the statements above were introduced for backwards compatibility with
SQLCipher 1.1 databases, we do not implement them as all SQLCipher databases
handled by Soledad should be created by SQLCipher >= 2.0.
"""
import logging
import os
import json
import u1db

from u1db import errors as u1db_errors
from u1db.backends import sqlite_backend

from hashlib import sha256
from functools import partial

from pysqlcipher import dbapi2 as sqlcipher_dbapi2

from twisted.internet import reactor
from twisted.internet import defer
from twisted.enterprise import adbapi

from leap.soledad.client.http_target import SoledadHTTPSyncTarget
from leap.soledad.client.sync import SoledadSynchronizer

from leap.soledad.client import pragmas
from leap.soledad.common.document import SoledadDocument


logger = logging.getLogger(__name__)


# Monkey-patch u1db.backends.sqlite_backend with pysqlcipher.dbapi2
sqlite_backend.dbapi2 = sqlcipher_dbapi2


def initialize_sqlcipher_db(opts, on_init=None, check_same_thread=True):
    """
    Initialize a SQLCipher database.

    :param opts:
    :type opts: SQLCipherOptions
    :param on_init: a tuple of queries to be executed on initialization
    :type on_init: tuple
    :return: pysqlcipher.dbapi2.Connection
    """
    # Note: There seemed to be a bug in sqlite 3.5.9 (with python2.6)
    #       where without re-opening the database on Windows, it
    #       doesn't see the transaction that was just committed
    # Removing from here now, look at the pysqlite implementation if the
    # bug shows up in windows.

    if not os.path.isfile(opts.path) and not opts.create:
        raise u1db_errors.DatabaseDoesNotExist()

    conn = sqlcipher_dbapi2.connect(
        opts.path, check_same_thread=check_same_thread)
    pragmas.set_init_pragmas(conn, opts, extra_queries=on_init)
    return conn


def initialize_sqlcipher_adbapi_db(opts, extra_queries=None):
    from leap.soledad.client import sqlcipher_adbapi
    return sqlcipher_adbapi.getConnectionPool(
        opts, extra_queries=extra_queries)


class SQLCipherOptions(object):
    """
    A container with options for the initialization of an SQLCipher database.
    """

    @classmethod
    def copy(cls, source, path=None, key=None, create=None,
             is_raw_key=None, cipher=None, kdf_iter=None,
             cipher_page_size=None, defer_encryption=None, sync_db_key=None):
        """
        Return a copy of C{source} with parameters different than None
        replaced by new values.
        """
        local_vars = locals()
        args = []
        kwargs = {}

        for name in ["path", "key"]:
            val = local_vars[name]
            if val is not None:
                args.append(val)
            else:
                args.append(getattr(source, name))

        for name in ["create", "is_raw_key", "cipher", "kdf_iter",
                     "cipher_page_size", "defer_encryption", "sync_db_key"]:
            val = local_vars[name]
            if val is not None:
                kwargs[name] = val
            else:
                kwargs[name] = getattr(source, name)

        return SQLCipherOptions(*args, **kwargs)

    def __init__(self, path, key, create=True, is_raw_key=False,
                 cipher='aes-256-cbc', kdf_iter=4000, cipher_page_size=1024,
                 defer_encryption=False, sync_db_key=None):
        """
        :param path: The filesystem path for the database to open.
        :type path: str
        :param create:
            True/False, should the database be created if it doesn't
            already exist?
        :param create: bool
        :param is_raw_key:
            Whether ``password`` is a raw 64-char hex string or a passphrase
            that should be hashed to obtain the encyrption key.
        :type raw_key: bool
        :param cipher: The cipher and mode to use.
        :type cipher: str
        :param kdf_iter: The number of iterations to use.
        :type kdf_iter: int
        :param cipher_page_size: The page size.
        :type cipher_page_size: int
        :param defer_encryption:
            Whether to defer encryption/decryption of documents, or do it
            inline while syncing.
        :type defer_encryption: bool
        """
        self.path = path
        self.key = key
        self.is_raw_key = is_raw_key
        self.create = create
        self.cipher = cipher
        self.kdf_iter = kdf_iter
        self.cipher_page_size = cipher_page_size
        self.defer_encryption = defer_encryption
        self.sync_db_key = sync_db_key

    def __str__(self):
        """
        Return string representation of options, for easy debugging.

        :return: String representation of options.
        :rtype: str
        """
        attr_names = filter(lambda a: not a.startswith('_'), dir(self))
        attr_str = []
        for a in attr_names:
            attr_str.append(a + "=" + str(getattr(self, a)))
        name = self.__class__.__name__
        return "%s(%s)" % (name, ', '.join(attr_str))


#
# The SQLCipher database
#

class SQLCipherDatabase(sqlite_backend.SQLitePartialExpandDatabase):
    """
    A U1DB implementation that uses SQLCipher as its persistence layer.
    """
    defer_encryption = False

    # The attribute _index_storage_value will be used as the lookup key for the
    # implementation of the SQLCipher storage backend.
    _index_storage_value = 'expand referenced encrypted'

    def __init__(self, opts):
        """
        Connect to an existing SQLCipher database, creating a new sqlcipher
        database file if needed.

        *** IMPORTANT ***

        Don't forget to close the database after use by calling the close()
        method otherwise some resources might not be freed and you may
        experience several kinds of leakages.

        *** IMPORTANT ***

        :param opts: options for initialization of the SQLCipher database.
        :type opts: SQLCipherOptions
        """
        # ensure the db is encrypted if the file already exists
        if os.path.isfile(opts.path):
            _assert_db_is_encrypted(opts)

        # connect to the sqlcipher database
        self._db_handle = initialize_sqlcipher_db(opts)

        # TODO ---------------------------------------------------
        # Everything else in this initialization has to be factored
        # out, so it can be used from SoledadSQLCipherWrapper.__init__
        # too.
        # ---------------------------------------------------------

        self._ensure_schema()
        self.set_document_factory(soledad_doc_factory)
        self._prime_replica_uid()

    def _prime_replica_uid(self):
        """
        In the u1db implementation, _replica_uid is a property
        that returns the value in _real_replica_uid, and does
        a db query if no value found.
        Here we prime the replica uid during initialization so
        that we don't have to wait for the query afterwards.
        """
        self._real_replica_uid = None
        self._get_replica_uid()

    def _extra_schema_init(self, c):
        """
        Add any extra fields, etc to the basic table definitions.

        This method is called by u1db.backends.sqlite_backend._initialize()
        method, which is executed when the database schema is created. Here,
        we use it to include the "syncable" property for LeapDocuments.

        :param c: The cursor for querying the database.
        :type c: dbapi2.cursor
        """
        c.execute(
            'ALTER TABLE document '
            'ADD COLUMN syncable BOOL NOT NULL DEFAULT TRUE')

    #
    # Document operations
    #

    def put_doc(self, doc):
        """
        Overwrite the put_doc method, to enqueue the modified document for
        encryption before sync.

        :param doc: The document to be put.
        :type doc: u1db.Document

        :return: The new document revision.
        :rtype: str
        """
        doc_rev = sqlite_backend.SQLitePartialExpandDatabase.put_doc(self, doc)
        if self.defer_encryption:
            # TODO move to api?
            self._sync_enc_pool.enqueue_doc_for_encryption(doc)
        return doc_rev

    #
    # SQLCipher API methods
    #

    # Extra query methods: extensions to the base u1db sqlite implmentation.

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
        :return: count.
        :rtype: int
        """
        c = self._db_handle.cursor()
        definition = self._get_index_definition(index_name)

        if len(key_values) != len(definition):
            raise u1db_errors.InvalidValueForIndex()
        tables = ["document_fields d%d" % i for i in range(len(definition))]
        novalue_where = ["d.doc_id = d%d.doc_id"
                         " AND d%d.field_name = ?"
                         % (i, i) for i in range(len(definition))]
        exact_where = [novalue_where[i] + (" AND d%d.value = ?" % (i,))
                       for i in range(len(definition))]
        args = []
        where = []
        for idx, (field, value) in enumerate(zip(definition, key_values)):
            args.append(field)
            where.append(exact_where[idx])
            args.append(value)

        tables = ["document_fields d%d" % i for i in range(len(definition))]
        statement = (
            "SELECT COUNT(*) FROM document d, %s WHERE %s " % (
                ', '.join(tables),
                ' AND '.join(where),
            ))
        try:
            c.execute(statement, tuple(args))
        except sqlcipher_dbapi2.OperationalError, e:
            raise sqlcipher_dbapi2.OperationalError(
                str(e) + '\nstatement: %s\nargs: %s\n' % (statement, args))
        res = c.fetchall()
        return res[0][0]

    def close(self):
        """
        Close db connections.
        """
        # TODO should be handled by adbapi instead
        # TODO syncdb should be stopped first

        if logger is not None:  # logger might be none if called from __del__
            logger.debug("SQLCipher backend: closing")

        # close the actual database
        if getattr(self, '_db_handle', False):
            self._db_handle.close()
            self._db_handle = None

    # indexes

    def _put_and_update_indexes(self, old_doc, doc):
        """
        Update a document and all indexes related to it.

        :param old_doc: The old version of the document.
        :type old_doc: u1db.Document
        :param doc: The new version of the document.
        :type doc: u1db.Document
        """
        sqlite_backend.SQLitePartialExpandDatabase._put_and_update_indexes(
            self, old_doc, doc)
        c = self._db_handle.cursor()
        c.execute('UPDATE document SET syncable=? WHERE doc_id=?',
                  (doc.syncable, doc.doc_id))

    def _get_doc(self, doc_id, check_for_conflicts=False):
        """
        Get just the document content, without fancy handling.

        :param doc_id: The unique document identifier
        :type doc_id: str
        :param include_deleted: If set to True, deleted documents will be
            returned with empty content. Otherwise asking for a deleted
            document will return None.
        :type include_deleted: bool

        :return: a Document object.
        :type: u1db.Document
        """
        doc = sqlite_backend.SQLitePartialExpandDatabase._get_doc(
            self, doc_id, check_for_conflicts)
        if doc:
            c = self._db_handle.cursor()
            c.execute('SELECT syncable FROM document WHERE doc_id=?',
                      (doc.doc_id,))
            result = c.fetchone()
            doc.syncable = bool(result[0])
        return doc

    def __del__(self):
        """
        Free resources when deleting or garbage collecting the database.

        This is only here to minimze problems if someone ever forgets to call
        the close() method after using the database; you should not rely on
        garbage collecting to free up the database resources.
        """
        self.close()


class SQLCipherU1DBSync(SQLCipherDatabase):
    """
    Soledad syncer implementation.
    """

    """
    The name of the local symmetrically encrypted documents to
    sync database file.
    """
    LOCAL_SYMMETRIC_SYNC_FILE_NAME = 'sync.u1db'

    """
    Period or recurrence of the Looping Call that will do the encryption to the
    syncdb (in seconds).
    """
    ENCRYPT_LOOP_PERIOD = 1

    def __init__(self, opts, soledad_crypto, replica_uid, cert_file,
                 defer_encryption=False, sync_db=None, sync_enc_pool=None):

        self._opts = opts
        self._path = opts.path
        self._crypto = soledad_crypto
        self.__replica_uid = replica_uid
        self._cert_file = cert_file
        self._sync_enc_pool = sync_enc_pool

        self._sync_db = sync_db

        # we store syncers in a dictionary indexed by the target URL. We also
        # store a hash of the auth info in case auth info expires and we need
        # to rebuild the syncer for that target. The final self._syncers
        # format is the following:
        #
        #  self._syncers = {'<url>': ('<auth_hash>', syncer), ...}

        self._syncers = {}

        # Storage for the documents received during a sync
        self.received_docs = []

        self.running = False

        self._reactor = reactor
        self._reactor.callWhenRunning(self._start)

        self._db_handle = None
        self._initialize_main_db()

        self.shutdownID = None

    @property
    def _replica_uid(self):
        return str(self.__replica_uid)

    def _start(self):
        if not self.running:
            self.shutdownID = self._reactor.addSystemEventTrigger(
                'during', 'shutdown', self.finalClose)
            self.running = True

    def _initialize_main_db(self):
        self._db_handle = initialize_sqlcipher_db(
            self._opts, check_same_thread=False)
        self._real_replica_uid = None
        self._ensure_schema()
        self.set_document_factory(soledad_doc_factory)

    @defer.inlineCallbacks
    def sync(self, url, creds=None, defer_decryption=True):
        """
        Synchronize documents with remote replica exposed at url.

        It is not safe to initiate more than one sync process and let them run
        concurrently. It is responsibility of the caller to ensure that there
        are no concurrent sync processes running. This is currently controlled
        by the main Soledad object because it may also run post-sync hooks,
        which should be run while the lock is locked.

        :param url: The url of the target replica to sync with.
        :type url: str
        :param creds: optional dictionary giving credentials to authorize the
                      operation with the server.
        :type creds: dict
        :param defer_decryption:
            Whether to defer the decryption process using the intermediate
            database. If False, decryption will be done inline.
        :type defer_decryption: bool

        :return:
            A Deferred, that will fire with the local generation (type `int`)
            before the synchronisation was performed.
        :rtype: Deferred
        """
        syncer = self._get_syncer(url, creds=creds)
        local_gen_before_sync = yield syncer.sync(
            defer_decryption=defer_decryption)
        self.received_docs = syncer.received_docs
        defer.returnValue(local_gen_before_sync)

    def _get_syncer(self, url, creds=None):
        """
        Get a synchronizer for ``url`` using ``creds``.

        :param url: The url of the target replica to sync with.
        :type url: str
        :param creds: optional dictionary giving credentials.
                      to authorize the operation with the server.
        :type creds: dict

        :return: A synchronizer.
        :rtype: Synchronizer
        """
        # we want to store at most one syncer for each url, so we also store a
        # hash of the connection credentials and replace the stored syncer for
        # a certain url if credentials have changed.
        h = sha256(json.dumps([url, creds])).hexdigest()
        cur_h, syncer = self._syncers.get(url, (None, None))
        if syncer is None or h != cur_h:
            syncer = SoledadSynchronizer(
                self,
                SoledadHTTPSyncTarget(
                    url,
                    # XXX is the replica_uid ready?
                    self._replica_uid,
                    creds=creds,
                    crypto=self._crypto,
                    cert_file=self._cert_file,
                    sync_db=self._sync_db,
                    sync_enc_pool=self._sync_enc_pool))
            self._syncers[url] = (h, syncer)
        # in order to reuse the same synchronizer multiple times we have to
        # reset its state (i.e. the number of documents received from target
        # and inserted in the local replica).
        syncer.num_inserted = 0
        return syncer

    #
    # Symmetric encryption of syncing docs
    #

    def get_generation(self):
        # FIXME
        # XXX this SHOULD BE a callback
        return self._get_generation()

    def finalClose(self):
        """
        This should only be called by the shutdown trigger.
        """
        self.shutdownID = None
        self.running = False

    def close(self):
        """
        Close the syncer and syncdb orderly
        """
        super(SQLCipherU1DBSync, self).close()
        # close all open syncers
        for url in self._syncers.keys():
            _, syncer = self._syncers[url]
            syncer.close()
            del self._syncers[url]


class U1DBSQLiteBackend(sqlite_backend.SQLitePartialExpandDatabase):
    """
    A very simple wrapper for u1db around sqlcipher backend.

    Instead of initializing the database on the fly, it just uses an existing
    connection that is passed to it in the initializer.

    It can be used in tests and debug runs to initialize the adbapi with plain
    sqlite connections, decoupled from the sqlcipher layer.
    """

    def __init__(self, conn):
        self._db_handle = conn
        self._real_replica_uid = None
        self._ensure_schema()
        self._factory = u1db.Document


class SoledadSQLCipherWrapper(SQLCipherDatabase):
    """
    A wrapper for u1db that uses the Soledad-extended sqlcipher backend.

    Instead of initializing the database on the fly, it just uses an existing
    connection that is passed to it in the initializer.

    It can be used from adbapi to initialize a soledad database after
    getting a regular connection to a sqlcipher database.
    """
    def __init__(self, conn, opts, sync_enc_pool):
        self._db_handle = conn
        self._real_replica_uid = None
        self._ensure_schema()
        self.set_document_factory(soledad_doc_factory)
        self._prime_replica_uid()
        self.defer_encryption = opts.defer_encryption
        self._sync_enc_pool = sync_enc_pool


def _assert_db_is_encrypted(opts):
    """
    Assert that the sqlcipher file contains an encrypted database.

    When opening an existing database, PRAGMA key will not immediately
    throw an error if the key provided is incorrect. To test that the
    database can be successfully opened with the provided key, it is
    necessary to perform some operation on the database (i.e. read from
    it) and confirm it is success.

    The easiest way to do this is select off the sqlite_master table,
    which will attempt to read the first page of the database and will
    parse the schema.

    :param opts:
    """
    # We try to open an encrypted database with the regular u1db
    # backend should raise a DatabaseError exception.
    # If the regular backend succeeds, then we need to stop because
    # the database was not properly initialized.
    try:
        sqlite_backend.SQLitePartialExpandDatabase(opts.path)
    except sqlcipher_dbapi2.DatabaseError:
        # assert that we can access it using SQLCipher with the given
        # key
        dummy_query = ('SELECT count(*) FROM sqlite_master',)
        initialize_sqlcipher_db(opts, on_init=dummy_query)
    else:
        raise DatabaseIsNotEncrypted()

#
# Exceptions
#


class DatabaseIsNotEncrypted(Exception):
    """
    Exception raised when trying to open non-encrypted databases.
    """
    pass


def soledad_doc_factory(doc_id=None, rev=None, json='{}', has_conflicts=False,
                        syncable=True):
    """
    Return a default Soledad Document.
    Used in the initialization for SQLCipherDatabase
    """
    return SoledadDocument(doc_id=doc_id, rev=rev, json=json,
                           has_conflicts=has_conflicts, syncable=syncable)

sqlite_backend.SQLiteDatabase.register_implementation(SQLCipherDatabase)


#
# twisted.enterprise.adbapi SQLCipher implementation
#

SQLCIPHER_CONNECTION_TIMEOUT = 10


def getConnectionPool(opts, extra_queries=None):
    openfun = partial(
        pragmas.set_init_pragmas,
        opts=opts,
        extra_queries=extra_queries)
    return SQLCipherConnectionPool(
        database=opts.path,
        check_same_thread=False,
        cp_openfun=openfun,
        timeout=SQLCIPHER_CONNECTION_TIMEOUT)


class SQLCipherConnection(adbapi.Connection):
    pass


class SQLCipherTransaction(adbapi.Transaction):
    pass


class SQLCipherConnectionPool(adbapi.ConnectionPool):

    connectionFactory = SQLCipherConnection
    transactionFactory = SQLCipherTransaction

    def __init__(self, *args, **kwargs):
        adbapi.ConnectionPool.__init__(
            self, "pysqlcipher.dbapi2", *args, **kwargs)
