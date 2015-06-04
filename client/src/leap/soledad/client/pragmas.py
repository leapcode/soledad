# -*- coding: utf-8 -*-
# pragmas.py
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
Different pragmas used in the initialization of the SQLCipher database.
"""
import logging
import string
import threading
import os

from leap.soledad.common import soledad_assert


logger = logging.getLogger(__name__)


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

    set_crypto_pragmas(conn, opts)

    if not nowal:
        set_write_ahead_logging(conn)
    if sync_off:
        set_synchronous_off(conn)
    else:
        set_synchronous_normal(conn)
    if memstore:
        set_mem_temp_store(conn)

    for query in extra_queries:
        conn.cursor().execute(query)


def set_crypto_pragmas(db_handle, sqlcipher_opts):
    """
    Set cryptographic params (key, cipher, KDF number of iterations and
    cipher page size).

    :param db_handle:
    :type db_handle:
    :param sqlcipher_opts: options for the SQLCipherDatabase
    :type sqlcipher_opts: SQLCipherOpts instance
    """
    # XXX assert CryptoOptions
    opts = sqlcipher_opts
    _set_key(db_handle, opts.key, opts.is_raw_key)
    _set_cipher(db_handle, opts.cipher)
    _set_kdf_iter(db_handle, opts.kdf_iter)
    _set_cipher_page_size(db_handle, opts.cipher_page_size)


def _set_key(db_handle, key, is_raw_key):
    """
    Set the ``key`` for use with the database.

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
    :param is_raw_key:
        Whether C{key} is a raw 64-char hex string or a passphrase that should
        be hashed to obtain the encyrption key.
    :type is_raw_key: bool
    """
    if is_raw_key:
        _set_key_raw(db_handle, key)
    else:
        _set_key_passphrase(db_handle, key)


def _set_key_passphrase(db_handle, passphrase):
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


def _set_key_raw(db_handle, key):
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


def _set_cipher(db_handle, cipher='aes-256-cbc'):
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


def _set_kdf_iter(db_handle, kdf_iter=4000):
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


def _set_cipher_page_size(db_handle, cipher_page_size=1024):
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


# XXX UNUSED ?
def set_rekey(db_handle, new_key, is_raw_key):
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
    :param is_raw_key: Whether C{password} is a raw 64-char hex string or a
                    passphrase that should be hashed to obtain the encyrption
                    key.
    :type is_raw_key: bool
    """
    if is_raw_key:
        _set_rekey_raw(db_handle, new_key)
    else:
        _set_rekey_passphrase(db_handle, new_key)


def _set_rekey_passphrase(db_handle, passphrase):
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


def _set_rekey_raw(db_handle, key):
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
    db_handle.cursor().execute('PRAGMA rekey = "x\'%s"' % key)


def set_synchronous_off(db_handle):
    """
    Change the setting of the "synchronous" flag to OFF.
    """
    logger.debug("SQLCIPHER: SETTING SYNCHRONOUS OFF")
    db_handle.cursor().execute('PRAGMA synchronous=OFF')


def set_synchronous_normal(db_handle):
    """
    Change the setting of the "synchronous" flag to NORMAL.
    """
    logger.debug("SQLCIPHER: SETTING SYNCHRONOUS NORMAL")
    db_handle.cursor().execute('PRAGMA synchronous=NORMAL')


def set_mem_temp_store(db_handle):
    """
    Use a in-memory store for temporary tables.
    """
    logger.debug("SQLCIPHER: SETTING TEMP_STORE MEMORY")
    db_handle.cursor().execute('PRAGMA temp_store=MEMORY')


def set_write_ahead_logging(db_handle):
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

    db_handle.cursor().execute('PRAGMA wal_autocheckpoint=50')


class NotAnHexString(Exception):
    """
    Raised when trying to (raw) key the database with a non-hex string.
    """
    pass
