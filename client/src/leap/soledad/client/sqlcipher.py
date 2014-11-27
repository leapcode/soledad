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
import string
import threading
import time
import json

from hashlib import sha256
from contextlib import contextmanager
from collections import defaultdict
from httplib import CannotSendRequest

from pysqlcipher import dbapi2
from u1db.backends import sqlite_backend
from u1db import errors as u1db_errors
from taskthread import TimerTask

from leap.soledad.client.crypto import SyncEncrypterPool, SyncDecrypterPool
from leap.soledad.client.target import SoledadSyncTarget
from leap.soledad.client.target import PendingReceivedDocsSyncError
from leap.soledad.client.sync import SoledadSynchronizer
from leap.soledad.client.mp_safe_db import MPSafeSQLiteDB
from leap.soledad.common import soledad_assert
from leap.soledad.common.document import SoledadDocument


logger = logging.getLogger(__name__)

# Monkey-patch u1db.backends.sqlite_backend with pysqlcipher.dbapi2
sqlite_backend.dbapi2 = dbapi2

# It seems that, as long as we are not using old sqlite versions, serialized
# mode is enabled by default at compile time. So accessing db connections from
# different threads should be safe, as long as no attempt is made to use them
# from multiple threads with no locking.
# See https://sqlite.org/threadsafe.html
# and http://bugs.python.org/issue16509

SQLITE_CHECK_SAME_THREAD = False

# We set isolation_level to None to setup autocommit mode.
# See: http://docs.python.org/2/library/sqlite3.html#controlling-transactions
# This avoids problems with sequential operations using the same soledad object
# trying to open new transactions
# (The error was:
# OperationalError:cannot start a transaction within a transaction.)
SQLITE_ISOLATION_LEVEL = None


def open(path, password, create=True, document_factory=None, crypto=None,
         raw_key=False, cipher='aes-256-cbc', kdf_iter=4000,
         cipher_page_size=1024, defer_encryption=False, sync_db_key=None):
    """
    Open a database at the given location.

    *** IMPORTANT ***

    Don't forget to close the database after use by calling the close()
    method otherwise some resources might not be freed and you may experience
    several kinds of leakages.

    *** IMPORTANT ***

    Will raise u1db.errors.DatabaseDoesNotExist if create=False and the
    database does not already exist.

    :param path: The filesystem path for the database to open.
    :type path: str
    :param create: True/False, should the database be created if it doesn't
        already exist?
    :param create: bool
    :param document_factory: A function that will be called with the same
        parameters as Document.__init__.
    :type document_factory: callable
    :param crypto: An instance of SoledadCrypto so we can encrypt/decrypt
        document contents when syncing.
    :type crypto: soledad.crypto.SoledadCrypto
    :param raw_key: Whether C{password} is a raw 64-char hex string or a
        passphrase that should be hashed to obtain the encyrption key.
    :type raw_key: bool
    :param cipher: The cipher and mode to use.
    :type cipher: str
    :param kdf_iter: The number of iterations to use.
    :type kdf_iter: int
    :param cipher_page_size: The page size.
    :type cipher_page_size: int
    :param defer_encryption: Whether to defer encryption/decryption of
                             documents, or do it inline while syncing.
    :type defer_encryption: bool

    :return: An instance of Database.
    :rtype SQLCipherDatabase
    """
    return SQLCipherDatabase.open_database(
        path, password, create=create, document_factory=document_factory,
        crypto=crypto, raw_key=raw_key, cipher=cipher, kdf_iter=kdf_iter,
        cipher_page_size=cipher_page_size, defer_encryption=defer_encryption,
        sync_db_key=sync_db_key)


#
# Exceptions
#

class DatabaseIsNotEncrypted(Exception):
    """
    Exception raised when trying to open non-encrypted databases.
    """
    pass


class NotAnHexString(Exception):
    """
    Raised when trying to (raw) key the database with a non-hex string.
    """
    pass


#
# The SQLCipher database
#

class SQLCipherDatabase(sqlite_backend.SQLitePartialExpandDatabase):
    """
    A U1DB implementation that uses SQLCipher as its persistence layer.
    """
    defer_encryption = False

    _index_storage_value = 'expand referenced encrypted'
    k_lock = threading.Lock()
    create_doc_lock = threading.Lock()
    update_indexes_lock = threading.Lock()
    _sync_watcher = None
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
    encrypting_lock = threading.Lock()

    """
    Period or recurrence of the periodic encrypting task, in seconds.
    """
    ENCRYPT_TASK_PERIOD = 1

    syncing_lock = defaultdict(threading.Lock)
    """
    A dictionary that hold locks which avoid multiple sync attempts from the
    same database replica.
    """

    def __init__(self, sqlcipher_file, password, document_factory=None,
                 crypto=None, raw_key=False, cipher='aes-256-cbc',
                 kdf_iter=4000, cipher_page_size=1024, sync_db_key=None):
        """
        Connect to an existing SQLCipher database, creating a new sqlcipher
        database file if needed.

        *** IMPORTANT ***

        Don't forget to close the database after use by calling the close()
        method otherwise some resources might not be freed and you may
        experience several kinds of leakages.

        *** IMPORTANT ***

        :param sqlcipher_file: The path for the SQLCipher file.
        :type sqlcipher_file: str
        :param password: The password that protects the SQLCipher db.
        :type password: str
        :param document_factory: A function that will be called with the same
                                 parameters as Document.__init__.
        :type document_factory: callable
        :param crypto: An instance of SoledadCrypto so we can encrypt/decrypt
                       document contents when syncing.
        :type crypto: soledad.crypto.SoledadCrypto
        :param raw_key: Whether password is a raw 64-char hex string or a
                        passphrase that should be hashed to obtain the
                        encyrption key.
        :type raw_key: bool
        :param cipher: The cipher and mode to use.
        :type cipher: str
        :param kdf_iter: The number of iterations to use.
        :type kdf_iter: int
        :param cipher_page_size: The page size.
        :type cipher_page_size: int
        """
        # ensure the db is encrypted if the file already exists
        if os.path.exists(sqlcipher_file):
            self.assert_db_is_encrypted(
                sqlcipher_file, password, raw_key, cipher, kdf_iter,
                cipher_page_size)

        # connect to the sqlcipher database
        with self.k_lock:
            self._db_handle = dbapi2.connect(
                sqlcipher_file,
                isolation_level=SQLITE_ISOLATION_LEVEL,
                check_same_thread=SQLITE_CHECK_SAME_THREAD)
            # set SQLCipher cryptographic parameters
            self._set_crypto_pragmas(
                self._db_handle, password, raw_key, cipher, kdf_iter,
                cipher_page_size)
            if os.environ.get('LEAP_SQLITE_NOSYNC'):
                self._pragma_synchronous_off(self._db_handle)
            else:
                self._pragma_synchronous_normal(self._db_handle)
            if os.environ.get('LEAP_SQLITE_MEMSTORE'):
                self._pragma_mem_temp_store(self._db_handle)
            self._pragma_write_ahead_logging(self._db_handle)
            self._real_replica_uid = None
            self._ensure_schema()
            self._crypto = crypto

        # define sync-db attrs
        self._sqlcipher_file = sqlcipher_file
        self._sync_db_key = sync_db_key
        self._sync_db = None
        self._sync_db_write_lock = None
        self._sync_enc_pool = None
        self.sync_queue = None

        if self.defer_encryption:
            # initialize sync db
            self._init_sync_db()
            # initialize syncing queue encryption pool
            self._sync_enc_pool = SyncEncrypterPool(
                self._crypto, self._sync_db, self._sync_db_write_lock)
            self._sync_watcher = TimerTask(self._encrypt_syncing_docs,
                                           self.ENCRYPT_TASK_PERIOD)
            self._sync_watcher.start()

        def factory(doc_id=None, rev=None, json='{}', has_conflicts=False,
                    syncable=True):
            return SoledadDocument(doc_id=doc_id, rev=rev, json=json,
                                   has_conflicts=has_conflicts,
                                   syncable=syncable)
        self.set_document_factory(factory)
        # we store syncers in a dictionary indexed by the target URL. We also
        # store a hash of the auth info in case auth info expires and we need
        # to rebuild the syncer for that target. The final self._syncers
        # format is the following:
        #
        #     self._syncers = {'<url>': ('<auth_hash>', syncer), ...}
        self._syncers = {}

    @classmethod
    def _open_database(cls, sqlcipher_file, password, document_factory=None,
                       crypto=None, raw_key=False, cipher='aes-256-cbc',
                       kdf_iter=4000, cipher_page_size=1024,
                       defer_encryption=False, sync_db_key=None):
        """
        Open a SQLCipher database.

        :param sqlcipher_file: The path for the SQLCipher file.
        :type sqlcipher_file: str
        :param password: The password that protects the SQLCipher db.
        :type password: str
        :param document_factory: A function that will be called with the same
            parameters as Document.__init__.
        :type document_factory: callable
        :param crypto: An instance of SoledadCrypto so we can encrypt/decrypt
            document contents when syncing.
        :type crypto: soledad.crypto.SoledadCrypto
        :param raw_key: Whether C{password} is a raw 64-char hex string or a
            passphrase that should be hashed to obtain the encyrption key.
        :type raw_key: bool
        :param cipher: The cipher and mode to use.
        :type cipher: str
        :param kdf_iter: The number of iterations to use.
        :type kdf_iter: int
        :param cipher_page_size: The page size.
        :type cipher_page_size: int
        :param defer_encryption: Whether to defer encryption/decryption of
                                 documents, or do it inline while syncing.
        :type defer_encryption: bool

        :return: The database object.
        :rtype: SQLCipherDatabase
        """
        cls.defer_encryption = defer_encryption
        if not os.path.isfile(sqlcipher_file):
            raise u1db_errors.DatabaseDoesNotExist()

        tries = 2
        # Note: There seems to be a bug in sqlite 3.5.9 (with python2.6)
        #       where without re-opening the database on Windows, it
        #       doesn't see the transaction that was just committed
        while True:

            with cls.k_lock:
                db_handle = dbapi2.connect(
                    sqlcipher_file,
                    check_same_thread=SQLITE_CHECK_SAME_THREAD)

                try:
                    # set cryptographic params
                    cls._set_crypto_pragmas(
                        db_handle, password, raw_key, cipher, kdf_iter,
                        cipher_page_size)
                    c = db_handle.cursor()
                    # XXX if we use it here, it should be public
                    v, err = cls._which_index_storage(c)
                except Exception as exc:
                    logger.warning("ERROR OPENING DATABASE!")
                    logger.debug("error was: %r" % exc)
                    v, err = None, exc
                finally:
                    db_handle.close()
                if v is not None:
                    break
            # possibly another process is initializing it, wait for it to be
            # done
            if tries == 0:
                raise err  # go for the richest error?
            tries -= 1
            time.sleep(cls.WAIT_FOR_PARALLEL_INIT_HALF_INTERVAL)
        return SQLCipherDatabase._sqlite_registry[v](
            sqlcipher_file, password, document_factory=document_factory,
            crypto=crypto, raw_key=raw_key, cipher=cipher, kdf_iter=kdf_iter,
            cipher_page_size=cipher_page_size, sync_db_key=sync_db_key)

    @classmethod
    def open_database(cls, sqlcipher_file, password, create, backend_cls=None,
                      document_factory=None, crypto=None, raw_key=False,
                      cipher='aes-256-cbc', kdf_iter=4000,
                      cipher_page_size=1024, defer_encryption=False,
                      sync_db_key=None):
        """
        Open a SQLCipher database.

        *** IMPORTANT ***

        Don't forget to close the database after use by calling the close()
        method otherwise some resources might not be freed and you may
        experience several kinds of leakages.

        *** IMPORTANT ***

        :param sqlcipher_file: The path for the SQLCipher file.
        :type sqlcipher_file: str

        :param password: The password that protects the SQLCipher db.
        :type password: str

        :param create: Should the datbase be created if it does not already
                       exist?
        :type create: bool

        :param backend_cls: A class to use as backend.
        :type backend_cls: type

        :param document_factory: A function that will be called with the same
                                 parameters as Document.__init__.
        :type document_factory: callable

        :param crypto: An instance of SoledadCrypto so we can encrypt/decrypt
                       document contents when syncing.
        :type crypto: soledad.crypto.SoledadCrypto

        :param raw_key: Whether C{password} is a raw 64-char hex string or a
                        passphrase that should be hashed to obtain the
                        encyrption key.
        :type raw_key: bool

        :param cipher: The cipher and mode to use.
        :type cipher: str

        :param kdf_iter: The number of iterations to use.
        :type kdf_iter: int

        :param cipher_page_size: The page size.
        :type cipher_page_size: int

        :param defer_encryption: Whether to defer encryption/decryption of
                                 documents, or do it inline while syncing.
        :type defer_encryption: bool

        :return: The database object.
        :rtype: SQLCipherDatabase
        """
        cls.defer_encryption = defer_encryption
        try:
            return cls._open_database(
                sqlcipher_file, password, document_factory=document_factory,
                crypto=crypto, raw_key=raw_key, cipher=cipher,
                kdf_iter=kdf_iter, cipher_page_size=cipher_page_size,
                defer_encryption=defer_encryption, sync_db_key=sync_db_key)
        except u1db_errors.DatabaseDoesNotExist:
            if not create:
                raise
            # TODO: remove backend class from here.
            if backend_cls is None:
                # default is SQLCipherPartialExpandDatabase
                backend_cls = SQLCipherDatabase
            return backend_cls(
                sqlcipher_file, password, document_factory=document_factory,
                crypto=crypto, raw_key=raw_key, cipher=cipher,
                kdf_iter=kdf_iter, cipher_page_size=cipher_page_size,
                sync_db_key=sync_db_key)

    def sync(self, url, creds=None, autocreate=True, defer_decryption=True):
        """
        Synchronize documents with remote replica exposed at url.

        There can be at most one instance syncing the same database replica at
        the same time, so this method will block until the syncing lock can be
        acquired.

        :param url: The url of the target replica to sync with.
        :type url: str
        :param creds: optional dictionary giving credentials.
            to authorize the operation with the server.
        :type creds: dict
        :param autocreate: Ask the target to create the db if non-existent.
        :type autocreate: bool
        :param defer_decryption: Whether to defer the decryption process using
                                 the intermediate database. If False,
                                 decryption will be done inline.
        :type defer_decryption: bool

        :return: The local generation before the synchronisation was performed.
        :rtype: int
        """
        res = None
        # the following context manager blocks until the syncing lock can be
        # acquired.
        if defer_decryption:
            self._init_sync_db()
        with self.syncer(url, creds=creds) as syncer:
            # XXX could mark the critical section here...
            try:
                res = syncer.sync(autocreate=autocreate,
                                  defer_decryption=defer_decryption)

            except PendingReceivedDocsSyncError:
                logger.warning("Local sync db is not clear, skipping sync...")
                return
            except CannotSendRequest:
                logger.warning("Connection with sync target couldn't be established. Resetting connection...")
                # closing the connection it will get it recreated in the next try
                syncer.sync_target.close()
                return

        return res

    def stop_sync(self):
        """
        Interrupt all ongoing syncs.
        """
        for url in self._syncers:
            _, syncer = self._syncers[url]
            syncer.stop()

    @contextmanager
    def syncer(self, url, creds=None):
        """
        Accesor for synchronizer.

        As we reuse the same synchronizer for every sync, there can be only
        one instance synchronizing the same database replica at the same time.
        Because of that, this method blocks until the syncing lock can be
        acquired.
        """
        with SQLCipherDatabase.syncing_lock[self._get_replica_uid()]:
            syncer = self._get_syncer(url, creds=creds)
            yield syncer

    @property
    def syncing(self):
        lock = SQLCipherDatabase.syncing_lock[self._get_replica_uid()]
        acquired_lock = lock.acquire(False)
        if acquired_lock is False:
            return True
        lock.release()
        return False

    def _get_syncer(self, url, creds=None):
        """
        Get a synchronizer for C{url} using C{creds}.

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

    def _init_sync_db(self):
        """
        Initialize the Symmetrically-Encrypted document to be synced database,
        and the queue to communicate with subprocess workers.
        """
        if self._sync_db is None:
            soledad_assert(self._sync_db_key is not None)
            sync_db_path = None
            if self._sqlcipher_file != ":memory:":
                sync_db_path = "%s-sync" % self._sqlcipher_file
            else:
                sync_db_path = ":memory:"
            self._sync_db = MPSafeSQLiteDB(sync_db_path)
            # protect the sync db with a password
            if self._sync_db_key is not None:
                self._set_crypto_pragmas(
                    self._sync_db, self._sync_db_key, False,
                    'aes-256-cbc', 4000, 1024)
            self._sync_db_write_lock = threading.Lock()
            self._create_sync_db_tables()
            self.sync_queue = multiprocessing.Queue()

    def _create_sync_db_tables(self):
        """
        Create tables for the local sync documents db if needed.
        """
        encr = SyncEncrypterPool
        decr = SyncDecrypterPool
        sql_encr = ("CREATE TABLE IF NOT EXISTS %s (%s)" % (
            encr.TABLE_NAME, encr.FIELD_NAMES))
        sql_decr = ("CREATE TABLE IF NOT EXISTS %s (%s)" % (
            decr.TABLE_NAME, decr.FIELD_NAMES))

        with self._sync_db_write_lock:
            self._sync_db.execute(sql_encr)
            self._sync_db.execute(sql_decr)

    #
    # Symmetric encryption of syncing docs
    #

    def _encrypt_syncing_docs(self):
        """
        Process the syncing queue and send the documents there
        to be encrypted in the sync db. They will be read by the
        SoledadSyncTarget during the sync_exchange.

        Called periodical from the TimerTask self._sync_watcher.
        """
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
        doc_rev = sqlite_backend.SQLitePartialExpandDatabase.put_doc(
            self, doc)
        if self.defer_encryption:
            self.sync_queue.put_nowait(doc)
        return doc_rev

    # indexes

    def _put_and_update_indexes(self, old_doc, doc):
        """
        Update a document and all indexes related to it.

        :param old_doc: The old version of the document.
        :type old_doc: u1db.Document
        :param doc: The new version of the document.
        :type doc: u1db.Document
        """
        with self.update_indexes_lock:
            sqlite_backend.SQLitePartialExpandDatabase._put_and_update_indexes(
                self, old_doc, doc)
            c = self._db_handle.cursor()
            c.execute('UPDATE document SET syncable=? '
                      'WHERE doc_id=?',
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
            c.execute('SELECT syncable FROM document '
                      'WHERE doc_id=?',
                      (doc.doc_id,))
            result = c.fetchone()
            doc.syncable = bool(result[0])
        return doc

    #
    # SQLCipher API methods
    #

    @classmethod
    def assert_db_is_encrypted(cls, sqlcipher_file, key, raw_key, cipher,
                               kdf_iter, cipher_page_size):
        """
        Assert that C{sqlcipher_file} contains an encrypted database.

        When opening an existing database, PRAGMA key will not immediately
        throw an error if the key provided is incorrect. To test that the
        database can be successfully opened with the provided key, it is
        necessary to perform some operation on the database (i.e. read from
        it) and confirm it is success.

        The easiest way to do this is select off the sqlite_master table,
        which will attempt to read the first page of the database and will
        parse the schema.

        :param sqlcipher_file: The path for the SQLCipher file.
        :type sqlcipher_file: str
        :param key: The key that protects the SQLCipher db.
        :type key: str
        :param raw_key: Whether C{key} is a raw 64-char hex string or a
            passphrase that should be hashed to obtain the encyrption key.
        :type raw_key: bool
        :param cipher: The cipher and mode to use.
        :type cipher: str
        :param kdf_iter: The number of iterations to use.
        :type kdf_iter: int
        :param cipher_page_size: The page size.
        :type cipher_page_size: int
        """
        try:
            # try to open an encrypted database with the regular u1db
            # backend should raise a DatabaseError exception.
            sqlite_backend.SQLitePartialExpandDatabase(sqlcipher_file)
            raise DatabaseIsNotEncrypted()
        except dbapi2.DatabaseError:
            # assert that we can access it using SQLCipher with the given
            # key
            with cls.k_lock:
                db_handle = dbapi2.connect(
                    sqlcipher_file,
                    isolation_level=SQLITE_ISOLATION_LEVEL,
                    check_same_thread=SQLITE_CHECK_SAME_THREAD)
                cls._set_crypto_pragmas(
                    db_handle, key, raw_key, cipher,
                    kdf_iter, cipher_page_size)
                db_handle.cursor().execute(
                    'SELECT count(*) FROM sqlite_master')

    @classmethod
    def _set_crypto_pragmas(cls, db_handle, key, raw_key, cipher, kdf_iter,
                            cipher_page_size):
        """
        Set cryptographic params (key, cipher, KDF number of iterations and
        cipher page size).
        """
        cls._pragma_key(db_handle, key, raw_key)
        cls._pragma_cipher(db_handle, cipher)
        cls._pragma_kdf_iter(db_handle, kdf_iter)
        cls._pragma_cipher_page_size(db_handle, cipher_page_size)

    @classmethod
    def _pragma_key(cls, db_handle, key, raw_key):
        """
        Set the C{key} for use with the database.

        The process of creating a new, encrypted database is called 'keying'
        the database. SQLCipher uses just-in-time key derivation at the point
        it is first needed for an operation. This means that the key (and any
        options) must be set before the first operation on the database. As
        soon as the database is touched (e.g. SELECT, CREATE TABLE, UPDATE,
        etc.) and pages need to be read or written, the key is prepared for
        use.

        Implementation Notes:

        * PRAGMA key should generally be called as the first operation on a
          database.

        :param key: The key for use with the database.
        :type key: str
        :param raw_key: Whether C{key} is a raw 64-char hex string or a
            passphrase that should be hashed to obtain the encyrption key.
        :type raw_key: bool
        """
        if raw_key:
            cls._pragma_key_raw(db_handle, key)
        else:
            cls._pragma_key_passphrase(db_handle, key)

    @classmethod
    def _pragma_key_passphrase(cls, db_handle, passphrase):
        """
        Set a passphrase for encryption key derivation.

        The key itself can be a passphrase, which is converted to a key using
        PBKDF2 key derivation. The result is used as the encryption key for
        the database. By using this method, there is no way to alter the KDF;
        if you want to do so you should use a raw key instead and derive the
        key using your own KDF.

        :param db_handle: A handle to the SQLCipher database.
        :type db_handle: pysqlcipher.Connection
        :param passphrase: The passphrase used to derive the encryption key.
        :type passphrase: str
        """
        db_handle.cursor().execute("PRAGMA key = '%s'" % passphrase)

    @classmethod
    def _pragma_key_raw(cls, db_handle, key):
        """
        Set a raw hexadecimal encryption key.

        It is possible to specify an exact byte sequence using a blob literal.
        With this method, it is the calling application's responsibility to
        ensure that the data provided is a 64 character hex string, which will
        be converted directly to 32 bytes (256 bits) of key data.

        :param db_handle: A handle to the SQLCipher database.
        :type db_handle: pysqlcipher.Connection
        :param key: A 64 character hex string.
        :type key: str
        """
        if not all(c in string.hexdigits for c in key):
            raise NotAnHexString(key)
        db_handle.cursor().execute('PRAGMA key = "x\'%s"' % key)

    @classmethod
    def _pragma_cipher(cls, db_handle, cipher='aes-256-cbc'):
        """
        Set the cipher and mode to use for symmetric encryption.

        SQLCipher uses aes-256-cbc as the default cipher and mode of
        operation. It is possible to change this, though not generally
        recommended, using PRAGMA cipher.

        SQLCipher makes direct use of libssl, so all cipher options available
        to libssl are also available for use with SQLCipher. See `man enc` for
        OpenSSL's supported ciphers.

        Implementation Notes:

        * PRAGMA cipher must be called after PRAGMA key and before the first
          actual database operation or it will have no effect.

        * If a non-default value is used PRAGMA cipher to create a database,
          it must also be called every time that database is opened.

        * SQLCipher does not implement its own encryption. Instead it uses the
          widely available and peer-reviewed OpenSSL libcrypto for all
          cryptographic functions.

        :param db_handle: A handle to the SQLCipher database.
        :type db_handle: pysqlcipher.Connection
        :param cipher: The cipher and mode to use.
        :type cipher: str
        """
        db_handle.cursor().execute("PRAGMA cipher = '%s'" % cipher)

    @classmethod
    def _pragma_kdf_iter(cls, db_handle, kdf_iter=4000):
        """
        Set the number of iterations for the key derivation function.

        SQLCipher uses PBKDF2 key derivation to strengthen the key and make it
        resistent to brute force and dictionary attacks. The default
        configuration uses 4000 PBKDF2 iterations (effectively 16,000 SHA1
        operations). PRAGMA kdf_iter can be used to increase or decrease the
        number of iterations used.

        Implementation Notes:

        * PRAGMA kdf_iter must be called after PRAGMA key and before the first
          actual database operation or it will have no effect.

        * If a non-default value is used PRAGMA kdf_iter to create a database,
          it must also be called every time that database is opened.

        * It is not recommended to reduce the number of iterations if a
          passphrase is in use.

        :param db_handle: A handle to the SQLCipher database.
        :type db_handle: pysqlcipher.Connection
        :param kdf_iter: The number of iterations to use.
        :type kdf_iter: int
        """
        db_handle.cursor().execute("PRAGMA kdf_iter = '%d'" % kdf_iter)

    @classmethod
    def _pragma_cipher_page_size(cls, db_handle, cipher_page_size=1024):
        """
        Set the page size of the encrypted database.

        SQLCipher 2 introduced the new PRAGMA cipher_page_size that can be
        used to adjust the page size for the encrypted database. The default
        page size is 1024 bytes, but it can be desirable for some applications
        to use a larger page size for increased performance. For instance,
        some recent testing shows that increasing the page size can noticeably
        improve performance (5-30%) for certain queries that manipulate a
        large number of pages (e.g. selects without an index, large inserts in
        a transaction, big deletes).

        To adjust the page size, call the pragma immediately after setting the
        key for the first time and each subsequent time that you open the
        database.

        Implementation Notes:

        * PRAGMA cipher_page_size must be called after PRAGMA key and before
          the first actual database operation or it will have no effect.

        * If a non-default value is used PRAGMA cipher_page_size to create a
          database, it must also be called every time that database is opened.

        :param db_handle: A handle to the SQLCipher database.
        :type db_handle: pysqlcipher.Connection
        :param cipher_page_size: The page size.
        :type cipher_page_size: int
        """
        db_handle.cursor().execute(
            "PRAGMA cipher_page_size = '%d'" % cipher_page_size)

    @classmethod
    def _pragma_rekey(cls, db_handle, new_key, raw_key):
        """
        Change the key of an existing encrypted database.

        To change the key on an existing encrypted database, it must first be
        unlocked with the current encryption key. Once the database is
        readable and writeable, PRAGMA rekey can be used to re-encrypt every
        page in the database with a new key.

        * PRAGMA rekey must be called after PRAGMA key. It can be called at any
          time once the database is readable.

        * PRAGMA rekey can not be used to encrypted a standard SQLite
          database! It is only useful for changing the key on an existing
          database.

        * Previous versions of SQLCipher provided a PRAGMA rekey_cipher and
          code>PRAGMA rekey_kdf_iter. These are deprecated and should not be
          used. Instead, use sqlcipher_export().

        :param db_handle: A handle to the SQLCipher database.
        :type db_handle: pysqlcipher.Connection
        :param new_key: The new key.
        :type new_key: str
        :param raw_key: Whether C{password} is a raw 64-char hex string or a
            passphrase that should be hashed to obtain the encyrption key.
        :type raw_key: bool
        """
        # XXX change key param!
        if raw_key:
            cls._pragma_rekey_raw(db_handle, key)
        else:
            cls._pragma_rekey_passphrase(db_handle, key)

    @classmethod
    def _pragma_rekey_passphrase(cls, db_handle, passphrase):
        """
        Change the passphrase for encryption key derivation.

        The key itself can be a passphrase, which is converted to a key using
        PBKDF2 key derivation. The result is used as the encryption key for
        the database.

        :param db_handle: A handle to the SQLCipher database.
        :type db_handle: pysqlcipher.Connection
        :param passphrase: The passphrase used to derive the encryption key.
        :type passphrase: str
        """
        db_handle.cursor().execute("PRAGMA rekey = '%s'" % passphrase)

    @classmethod
    def _pragma_rekey_raw(cls, db_handle, key):
        """
        Change the raw hexadecimal encryption key.

        It is possible to specify an exact byte sequence using a blob literal.
        With this method, it is the calling application's responsibility to
        ensure that the data provided is a 64 character hex string, which will
        be converted directly to 32 bytes (256 bits) of key data.

        :param db_handle: A handle to the SQLCipher database.
        :type db_handle: pysqlcipher.Connection
        :param key: A 64 character hex string.
        :type key: str
        """
        if not all(c in string.hexdigits for c in key):
            raise NotAnHexString(key)
        # XXX change passphrase param!
        db_handle.cursor().execute('PRAGMA rekey = "x\'%s"' % passphrase)

    @classmethod
    def _pragma_synchronous_off(cls, db_handle):
        """
        Change the setting of the "synchronous" flag to OFF.
        """
        logger.debug("SQLCIPHER: SETTING SYNCHRONOUS OFF")
        db_handle.cursor().execute('PRAGMA synchronous=OFF')

    @classmethod
    def _pragma_synchronous_normal(cls, db_handle):
        """
        Change the setting of the "synchronous" flag to NORMAL.
        """
        logger.debug("SQLCIPHER: SETTING SYNCHRONOUS NORMAL")
        db_handle.cursor().execute('PRAGMA synchronous=NORMAL')

    @classmethod
    def _pragma_mem_temp_store(cls, db_handle):
        """
        Use a in-memory store for temporary tables.
        """
        logger.debug("SQLCIPHER: SETTING TEMP_STORE MEMORY")
        db_handle.cursor().execute('PRAGMA temp_store=MEMORY')

    @classmethod
    def _pragma_write_ahead_logging(cls, db_handle):
        """
        Enable write-ahead logging, and set the autocheckpoint to 50 pages.

        Setting the autocheckpoint to a small value, we make the reads not
        suffer too much performance degradation.

        From the sqlite docs:

        "There is a tradeoff between average read performance and average write
        performance. To maximize the read performance, one wants to keep the
        WAL as small as possible and hence run checkpoints frequently, perhaps
        as often as every COMMIT. To maximize write performance, one wants to
        amortize the cost of each checkpoint over as many writes as possible,
        meaning that one wants to run checkpoints infrequently and let the WAL
        grow as large as possible before each checkpoint. The decision of how
        often to run checkpoints may therefore vary from one application to
        another depending on the relative read and write performance
        requirements of the application. The default strategy is to run a
        checkpoint once the WAL reaches 1000 pages"
        """
        logger.debug("SQLCIPHER: SETTING WRITE-AHEAD LOGGING")
        db_handle.cursor().execute('PRAGMA journal_mode=WAL')
        # The optimum value can still use a little bit of tuning, but we favor
        # small sizes of the WAL file to get fast reads, since we assume that
        # the writes will be quick enough to not block too much.

        # TODO
        # As a further improvement, we might want to set autocheckpoint to 0
        # here and do the checkpoints manually in a separate thread, to avoid
        # any blocks in the main thread (we should run a loopingcall from here)
        db_handle.cursor().execute('PRAGMA wal_autocheckpoint=50')

    # Extra query methods: extensions to the base sqlite implmentation.

    def get_count_from_index(self, index_name, *key_values):
        """
        Returns the count for a given combination of index_name
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
        except dbapi2.OperationalError, e:
            raise dbapi2.OperationalError(
                str(e) + '\nstatement: %s\nargs: %s\n' % (statement, args))
        res = c.fetchall()
        return res[0][0]

    def close(self):
        """
        Close db_handle and close syncer.
        """
        if logger is not None:  # logger might be none if called from __del__
            logger.debug("Sqlcipher backend: closing")
        # stop the sync watcher for deferred encryption
        if self._sync_watcher is not None:
            self._sync_watcher.stop()
            self._sync_watcher.shutdown()
            self._sync_watcher = None
        # close all open syncers
        for url in self._syncers:
            _, syncer = self._syncers[url]
            syncer.close()
        self._syncers = []
        # stop the encryption pool
        if self._sync_enc_pool is not None:
            self._sync_enc_pool.close()
            self._sync_enc_pool = None
        # close the actual database
        if self._db_handle is not None:
            self._db_handle.close()
            self._db_handle = None
        # close the sync database
        if self._sync_db is not None:
            self._sync_db.close()
            self._sync_db = None
        # close the sync queue
        if self.sync_queue is not None:
            self.sync_queue.close()
            del self.sync_queue
            self.sync_queue = None

    def __del__(self):
        """
        Free resources when deleting or garbage collecting the database.

        This is only here to minimze problems if someone ever forgets to call
        the close() method after using the database; you should not rely on
        garbage collecting to free up the database resources.
        """
        self.close()

    @property
    def replica_uid(self):
        return self._get_replica_uid()


sqlite_backend.SQLiteDatabase.register_implementation(SQLCipherDatabase)
