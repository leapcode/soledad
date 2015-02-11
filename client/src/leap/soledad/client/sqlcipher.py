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
import multiprocessing
import os
import threading
import json
import u1db

from u1db import errors as u1db_errors
from u1db.backends import sqlite_backend

from hashlib import sha256
from contextlib import contextmanager
from collections import defaultdict
from httplib import CannotSendRequest

from pysqlcipher import dbapi2 as sqlcipher_dbapi2

from twisted.internet import reactor
from twisted.internet.task import LoopingCall
from twisted.internet.threads import deferToThreadPool
from twisted.python.threadpool import ThreadPool
from twisted.python import log

from leap.soledad.client import crypto
from leap.soledad.client.target import SoledadSyncTarget
from leap.soledad.client.target import PendingReceivedDocsSyncError
from leap.soledad.client.sync import SoledadSynchronizer

from leap.soledad.client import pragmas
from leap.soledad.common import soledad_assert
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
    set_init_pragmas(conn, opts, extra_queries=on_init)
    return conn


_db_init_lock = threading.Lock()


def set_init_pragmas(conn, opts=None, extra_queries=None):
    """
    Set the initialization pragmas.

    This includes the crypto pragmas, and any other options that must
    be passed early to sqlcipher db.
    """
    soledad_assert(opts is not None)
    extra_queries = [] if extra_queries is None else extra_queries
    with _db_init_lock:
        # only one execution path should initialize the db
        _set_init_pragmas(conn, opts, extra_queries)


def _set_init_pragmas(conn, opts, extra_queries):

    sync_off = os.environ.get('LEAP_SQLITE_NOSYNC')
    memstore = os.environ.get('LEAP_SQLITE_MEMSTORE')
    nowal = os.environ.get('LEAP_SQLITE_NOWAL')

    pragmas.set_crypto_pragmas(conn, opts)

    if not nowal:
        pragmas.set_write_ahead_logging(conn)
    if sync_off:
        pragmas.set_synchronous_off(conn)
    else:
        pragmas.set_synchronous_normal(conn)
    if memstore:
        pragmas.set_mem_temp_store(conn)

    for query in extra_queries:
        conn.cursor().execute(query)


class SQLCipherOptions(object):
    """
    A container with options for the initialization of an SQLCipher database.
    """

    @classmethod
    def copy(cls, source, path=None, key=None, create=None,
            is_raw_key=None, cipher=None, kdf_iter=None, cipher_page_size=None,
            defer_encryption=None, sync_db_key=None):
        """
        Return a copy of C{source} with parameters different than None
        replaced by new values.
        """
        return SQLCipherOptions(
            path if path else source.path,
            key if key else source.key,
            create=create if create else source.create,
            is_raw_key=is_raw_key if is_raw_key else source.is_raw_key,
            cipher=cipher if cipher else source.cipher,
            kdf_iter=kdf_iter if kdf_iter else source.kdf_iter,
            cipher_page_size=cipher_page_size if cipher_page_size else source.cipher_page_size,
            defer_encryption=defer_encryption if defer_encryption else source.defer_encryption,
            sync_db_key=sync_db_key if sync_db_key else source.sync_db_key)

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

        # TODO XXX move to API XXX
        if self.defer_encryption:
            self.sync_queue.put_nowait(doc)
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
        exact_where = [novalue_where[i]
                       + (" AND d%d.value = ?" % (i,))
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

    _sync_loop = None
    _sync_enc_pool = None

    """
    The name of the local symmetrically encrypted documents to
    sync database file.
    """
    LOCAL_SYMMETRIC_SYNC_FILE_NAME = 'sync.u1db'

    """
    A dictionary that hold locks which avoid multiple sync attempts from the
    same database replica.
    """
    # XXX We do not need the lock here now. Remove.
    encrypting_lock = threading.Lock()

    """
    Period or recurrence of the Looping Call that will do the encryption to the
    syncdb (in seconds).
    """
    ENCRYPT_LOOP_PERIOD = 1

    """
    A dictionary that hold locks which avoid multiple sync attempts from the
    same database replica.
    """
    syncing_lock = defaultdict(threading.Lock)

    def __init__(self, opts, soledad_crypto, replica_uid,
                 defer_encryption=False):

        self._opts = opts
        self._path = opts.path
        self._crypto = soledad_crypto
        self.__replica_uid = replica_uid

        self._sync_db_key = opts.sync_db_key
        self._sync_db = None
        self._sync_db_write_lock = None
        self._sync_enc_pool = None
        self.sync_queue = None

        # we store syncers in a dictionary indexed by the target URL. We also
        # store a hash of the auth info in case auth info expires and we need
        # to rebuild the syncer for that target. The final self._syncers
        # format is the following:
        #
        #  self._syncers = {'<url>': ('<auth_hash>', syncer), ...}

        self._syncers = {}
        self._sync_db_write_lock = threading.Lock()
        self.sync_queue = multiprocessing.Queue()

        self.running = False
        self._sync_threadpool = None
        self._initialize_sync_threadpool()

        self._reactor = reactor
        self._reactor.callWhenRunning(self._start)

        self.ready = True
        self._db_handle = None
        self._initialize_syncer_main_db()

        if defer_encryption:
            self._initialize_sync_db(opts)

            # initialize syncing queue encryption pool
            self._sync_enc_pool = crypto.SyncEncrypterPool(
                self._crypto, self._sync_db, self._sync_db_write_lock)

            # -----------------------------------------------------------------
            # From the documentation: If f returns a deferred, rescheduling
            # will not take place until the deferred has fired. The result
            # value is ignored.

            # TODO use this to avoid multiple sync attempts if the sync has not
            # finished!
            # -----------------------------------------------------------------

            # XXX this was called sync_watcher --- trace any remnants
            self._sync_loop = LoopingCall(self._encrypt_syncing_docs)
            self._sync_loop.start(self.ENCRYPT_LOOP_PERIOD)

        self.shutdownID = None

    @property
    def _replica_uid(self):
        return str(self.__replica_uid)

    def _start(self):
        if not self.running:
            self._sync_threadpool.start()
            self.shutdownID = self._reactor.addSystemEventTrigger(
                'during', 'shutdown', self.finalClose)
            self.running = True

    def _defer_to_sync_threadpool(self, meth, *args, **kwargs):
        return deferToThreadPool(
            self._reactor, self._sync_threadpool, meth, *args, **kwargs)

    def _initialize_syncer_main_db(self):

        def init_db():

            # XXX DEBUG -----------------------------------------
            # REMOVE ME when merging.

            #import thread
            #print "initializing in thread", thread.get_ident()
            # ---------------------------------------------------
            self._db_handle = initialize_sqlcipher_db(
                self._opts, check_same_thread=False)
            self._real_replica_uid = None
            self._ensure_schema()
            self.set_document_factory(soledad_doc_factory)

        return self._defer_to_sync_threadpool(init_db)

    def _initialize_sync_threadpool(self):
        """
        Initialize a ThreadPool with exactly one thread, that will be used to
        run all the network blocking calls for syncing on a separate thread.

        TODO this needs to be ported away from urllib and into twisted async
        calls, and then we can ditch this syncing thread and reintegrate into
        the main reactor.
        """
        self._sync_threadpool = ThreadPool(0, 1)

    def _initialize_sync_db(self, opts):
        """
        Initialize the Symmetrically-Encrypted document to be synced database,
        and the queue to communicate with subprocess workers.

        :param opts:
        :type opts: SQLCipherOptions
        """
        soledad_assert(opts.sync_db_key is not None)
        sync_db_path = None
        if opts.path != ":memory:":
            sync_db_path = "%s-sync" % opts.path
        else:
            sync_db_path = ":memory:"

        # we copy incoming options because the opts object might be used
        # somewhere else
        sync_opts = SQLCipherOptions.copy(
            opts, path=sync_db_path, create=True)
        self._sync_db = initialize_sqlcipher_db(
            sync_opts, on_init=self._sync_db_extra_init,
            check_same_thread=False)
        pragmas.set_crypto_pragmas(self._sync_db, opts)
        # ---------------------------------------------------------

    @property
    def _sync_db_extra_init(self):
        """
        Queries for creating tables for the local sync documents db if needed.
        They are passed as extra initialization to initialize_sqlciphjer_db

        :rtype: tuple of strings
        """
        maybe_create = "CREATE TABLE IF NOT EXISTS %s (%s)"
        encr = crypto.SyncEncrypterPool
        decr = crypto.SyncDecrypterPool
        sql_encr_table_query = (maybe_create % (
            encr.TABLE_NAME, encr.FIELD_NAMES))
        sql_decr_table_query = (maybe_create % (
            decr.TABLE_NAME, decr.FIELD_NAMES))
        return (sql_encr_table_query, sql_decr_table_query)

    def sync(self, url, creds=None, autocreate=True, defer_decryption=True):
        """
        Synchronize documents with remote replica exposed at url.

        There can be at most one instance syncing the same database replica at
        the same time, so this method will block until the syncing lock can be
        acquired.

        :param url: The url of the target replica to sync with.
        :type url: str
        :param creds:
            optional dictionary giving credentials.
            to authorize the operation with the server.
        :type creds: dict
        :param autocreate: Ask the target to create the db if non-existent.
        :type autocreate: bool
        :param defer_decryption:
            Whether to defer the decryption process using the intermediate
            database. If False, decryption will be done inline.
        :type defer_decryption: bool

        :return:
            A Deferred, that will fire with the local generation (type `int`)
            before the synchronisation was performed.
        :rtype: deferred
        """
        if not self.ready:
            print "not ready yet..."
            # XXX ---------------------------------------------------------
            # This might happen because the database has not yet been
            # initialized (it's deferred to the theadpool).
            # A good strategy might involve to return a deferred that will
            # callLater this same function after a timeout (deferLater)
            # Might want to keep track of retries and cancel too.
            # --------------------------------------------------------------
        kwargs = {'creds': creds, 'autocreate': autocreate,
                  'defer_decryption': defer_decryption}
        return self._defer_to_sync_threadpool(self._sync, url, **kwargs)

    def _sync(self, url, creds=None, autocreate=True, defer_decryption=True):
        res = None

        # the following context manager blocks until the syncing lock can be
        # acquired.
        # TODO review, I think this is no longer needed with a 1-thread
        # threadpool.

        log.msg("in _sync")
        self.__url = url
        with self._syncer(url, creds=creds) as syncer:
            # XXX could mark the critical section here...
            try:
                log.msg('syncer sync...')
                res = syncer.sync(autocreate=autocreate,
                                  defer_decryption=defer_decryption)

            except PendingReceivedDocsSyncError:
                logger.warning("Local sync db is not clear, skipping sync...")
                return
            except CannotSendRequest:
                logger.warning("Connection with sync target couldn't be "
                               "established. Resetting connection...")
                # closing the connection it will be recreated in the next try
                syncer.sync_target.close()
                return

        return res

    def stop_sync(self):
        """
        Interrupt all ongoing syncs.
        """
        self._stop_sync()

    def _stop_sync(self):
        for url in self._syncers:
            _, syncer = self._syncers[url]
            syncer.stop()

    @contextmanager
    def _syncer(self, url, creds=None):
        """
        Accesor for synchronizer.

        As we reuse the same synchronizer for every sync, there can be only
        one instance synchronizing the same database replica at the same time.
        Because of that, this method blocks until the syncing lock can be
        acquired.
        """
        with self.syncing_lock[self._path]:
            syncer = self._get_syncer(url, creds=creds)
            yield syncer

    @property
    def syncing(self):
        lock = self.syncing_lock[self._path]
        acquired_lock = lock.acquire(False)
        if acquired_lock is False:
            return True
        lock.release()
        return False

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
            wlock = self._sync_db_write_lock
            syncer = SoledadSynchronizer(
                self,
                SoledadSyncTarget(url,
                                  # XXX is the replica_uid ready?
                                  self._replica_uid,
                                  creds=creds,
                                  crypto=self._crypto,
                                  sync_db=self._sync_db,
                                  sync_db_write_lock=wlock))
            self._syncers[url] = (h, syncer)
        # in order to reuse the same synchronizer multiple times we have to
        # reset its state (i.e. the number of documents received from target
        # and inserted in the local replica).
        syncer.num_inserted = 0
        return syncer

    #
    # Symmetric encryption of syncing docs
    #

    def _encrypt_syncing_docs(self):
        """
        Process the syncing queue and send the documents there
        to be encrypted in the sync db. They will be read by the
        SoledadSyncTarget during the sync_exchange.

        Called periodically from the LoopingCall self._sync_loop.
        """
        # TODO should return a deferred that would firewhen the encryption is
        # done. See note on __init__

        lock = self.encrypting_lock
        # optional wait flag used to avoid blocking
        if not lock.acquire(False):
            return
        else:
            queue = self.sync_queue
            try:
                while not queue.empty():
                    doc = queue.get_nowait()
                    self._sync_enc_pool.encrypt_doc(doc)

            except Exception as exc:
                logger.error("Error while  encrypting docs to sync")
                logger.exception(exc)
            finally:
                lock.release()

    def get_generation(self):
        # FIXME
        # XXX this SHOULD BE a callback
        return self._get_generation()

    def finalClose(self):
        """
        This should only be called by the shutdown trigger.
        """
        self.shutdownID = None
        self._sync_threadpool.stop()
        self.running = False

    def close(self):
        """
        Close the syncer and syncdb orderly
        """
        # stop the sync loop for deferred encryption
        if self._sync_loop is not None:
            self._sync_loop.reset()
            self._sync_loop.stop()
            self._sync_loop = None
        # close all open syncers
        for url in self._syncers:
            _, syncer = self._syncers[url]
            syncer.close()
        self._syncers = []
        # stop the encryption pool
        if self._sync_enc_pool is not None:
            self._sync_enc_pool.close()
            self._sync_enc_pool = None

        # close the sync database
        if self._sync_db is not None:
            self._sync_db.close()
            self._sync_db = None
        # close the sync queue
        if self.sync_queue is not None:
            self.sync_queue.close()
            del self.sync_queue
            self.sync_queue = None


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
    def __init__(self, conn):
        self._db_handle = conn
        self._real_replica_uid = None
        self._ensure_schema()
        self.set_document_factory(soledad_doc_factory)
        self._prime_replica_uid()


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
