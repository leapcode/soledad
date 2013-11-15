# -*- coding: utf-8 -*-
# sqlcipher.py
# Copyright (C) 2013 LEAP
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
SLCipher 1.1 databases, we do not implement them as all SQLCipher databases
handled by Soledad should be created by SQLCipher >= 2.0.
"""
import logging
import os
import time
import string
import threading


from u1db.backends import sqlite_backend
from pysqlcipher import dbapi2
from u1db import errors as u1db_errors
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
         cipher_page_size=1024):
    """Open a database at the given location.

    Will raise u1db.errors.DatabaseDoesNotExist if create=False and the
    database does not already exist.

    :param path: The filesystem path for the database to open.
    :param type: str
    :param create: True/False, should the database be created if it doesn't
        already exist?
    :param type: bool
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

    :return: An instance of Database.
    :rtype SQLCipherDatabase
    """
    return SQLCipherDatabase.open_database(
        path, password, create=create, document_factory=document_factory,
        crypto=crypto, raw_key=raw_key, cipher=cipher, kdf_iter=kdf_iter,
        cipher_page_size=cipher_page_size)


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
    """A U1DB implementation that uses SQLCipher as its persistence layer."""

    _index_storage_value = 'expand referenced encrypted'
    k_lock = threading.Lock()

    def __init__(self, sqlcipher_file, password, document_factory=None,
                 crypto=None, raw_key=False, cipher='aes-256-cbc',
                 kdf_iter=4000, cipher_page_size=1024):
        """
        Create a new sqlcipher file.

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
        """
        # ensure the db is encrypted if the file already exists
        if os.path.exists(sqlcipher_file):
            self.assert_db_is_encrypted(
                sqlcipher_file, password, raw_key, cipher, kdf_iter,
                cipher_page_size)
        # connect to the database
        with self.k_lock:
            self._db_handle = dbapi2.connect(
                sqlcipher_file,
                isolation_level=SQLITE_ISOLATION_LEVEL,
                check_same_thread=SQLITE_CHECK_SAME_THREAD)
            # set SQLCipher cryptographic parameters
            self._set_crypto_pragmas(
                self._db_handle, password, raw_key, cipher, kdf_iter,
                cipher_page_size)
            self._real_replica_uid = None
            self._ensure_schema()
            self._crypto = crypto

        def factory(doc_id=None, rev=None, json='{}', has_conflicts=False,
                    syncable=True):
            return SoledadDocument(doc_id=doc_id, rev=rev, json=json,
                                   has_conflicts=has_conflicts,
                                   syncable=syncable)
        self.set_document_factory(factory)

    @classmethod
    def _open_database(cls, sqlcipher_file, password, document_factory=None,
                       crypto=None, raw_key=False, cipher='aes-256-cbc',
                       kdf_iter=4000, cipher_page_size=1024):
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

        :return: The database object.
        :rtype: SQLCipherDatabase
        """
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
            cipher_page_size=cipher_page_size)

    @classmethod
    def open_database(cls, sqlcipher_file, password, create, backend_cls=None,
                      document_factory=None, crypto=None, raw_key=False,
                      cipher='aes-256-cbc', kdf_iter=4000,
                      cipher_page_size=1024):
        """
        Open a SQLCipher database.

        :param sqlcipher_file: The path for the SQLCipher file.
        :type sqlcipher_file: str
        :param password: The password that protects the SQLCipher db.
        :type password: str
        :param create: Should the datbase be created if it does not already
            exist?
        :type: bool
        :param backend_cls: A class to use as backend.
        :type backend_cls: type
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

        :return: The database object.
        :rtype: SQLCipherDatabase
        """
        try:
            return cls._open_database(
                sqlcipher_file, password, document_factory=document_factory,
                crypto=crypto, raw_key=raw_key, cipher=cipher,
                kdf_iter=kdf_iter, cipher_page_size=cipher_page_size)
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
                kdf_iter=kdf_iter, cipher_page_size=cipher_page_size)

    def sync(self, url, creds=None, autocreate=True):
        """
        Synchronize documents with remote replica exposed at url.

        :param url: The url of the target replica to sync with.
        :type url: str
        :param creds: optional dictionary giving credentials.
            to authorize the operation with the server.
        :type creds: dict
        :param autocreate: Ask the target to create the db if non-existent.
        :type autocreate: bool

        :return: The local generation before the synchronisation was performed.
        :rtype: int
        """
        from u1db.sync import Synchronizer
        from leap.soledad.client.target import SoledadSyncTarget
        return Synchronizer(
            self,
            SoledadSyncTarget(url,
                              creds=creds,
                              crypto=self._crypto)).sync(autocreate=autocreate)

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

    def __del__(self):
        """
        Closes db_handle upon object destruction.
        """
        if self._db_handle is not None:
            self._db_handle.close()


sqlite_backend.SQLiteDatabase.register_implementation(SQLCipherDatabase)
