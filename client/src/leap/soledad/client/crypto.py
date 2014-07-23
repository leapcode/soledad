# -*- coding: utf-8 -*-
# crypto.py
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
Cryptographic utilities for Soledad.
"""
import os
import binascii
import hmac
import hashlib
import json
import logging
import multiprocessing
import threading

from pycryptopp.cipher.aes import AES
from pycryptopp.cipher.xsalsa20 import XSalsa20
from zope.proxy import sameProxiedObjects

from leap.soledad.common import soledad_assert
from leap.soledad.common import soledad_assert_type
from leap.soledad.common.document import SoledadDocument


from leap.soledad.common.crypto import (
    EncryptionSchemes,
    UnknownEncryptionScheme,
    MacMethods,
    UnknownMacMethod,
    WrongMac,
    ENC_JSON_KEY,
    ENC_SCHEME_KEY,
    ENC_METHOD_KEY,
    ENC_IV_KEY,
    MAC_KEY,
    MAC_METHOD_KEY,
)

logger = logging.getLogger(__name__)


MAC_KEY_LENGTH = 64


class EncryptionMethods(object):
    """
    Representation of encryption methods that can be used.
    """

    AES_256_CTR = 'aes-256-ctr'
    XSALSA20 = 'xsalsa20'

#
# Exceptions
#


class DocumentNotEncrypted(Exception):
    """
    Raised for failures in document encryption.
    """
    pass


class UnknownEncryptionMethod(Exception):
    """
    Raised when trying to encrypt/decrypt with unknown method.
    """
    pass


class NoSymmetricSecret(Exception):
    """
    Raised when trying to get a hashed passphrase.
    """


def encrypt_sym(data, key, method):
    """
    Encrypt C{data} using a {password}.

    Currently, the only encryption methods supported are AES-256 in CTR
    mode and XSalsa20.

    :param data: The data to be encrypted.
    :type data: str
    :param key: The key used to encrypt C{data} (must be 256 bits long).
    :type key: str
    :param method: The encryption method to use.
    :type method: str

    :return: A tuple with the initial value and the encrypted data.
    :rtype: (long, str)
    """
    soledad_assert_type(key, str)

    soledad_assert(
        len(key) == 32,  # 32 x 8 = 256 bits.
        'Wrong key size: %s bits (must be 256 bits long).' %
        (len(key) * 8))
    iv = None
    # AES-256 in CTR mode
    if method == EncryptionMethods.AES_256_CTR:
        iv = os.urandom(16)
        ciphertext = AES(key=key, iv=iv).process(data)
    # XSalsa20
    elif method == EncryptionMethods.XSALSA20:
        iv = os.urandom(24)
        ciphertext = XSalsa20(key=key, iv=iv).process(data)
    else:
        # raise if method is unknown
        raise UnknownEncryptionMethod('Unkwnown method: %s' % method)
    return binascii.b2a_base64(iv), ciphertext


def decrypt_sym(data, key, method, **kwargs):
    """
    Decrypt data using symmetric secret.

    Currently, the only encryption method supported is AES-256 CTR mode.

    :param data: The data to be decrypted.
    :type data: str
    :param key: The key used to decrypt C{data} (must be 256 bits long).
    :type key: str
    :param method: The encryption method to use.
    :type method: str
    :param kwargs: Other parameters specific to each encryption method.
    :type kwargs: dict

    :return: The decrypted data.
    :rtype: str
    """
    soledad_assert_type(key, str)
    # assert params
    soledad_assert(
        len(key) == 32,  # 32 x 8 = 256 bits.
        'Wrong key size: %s (must be 256 bits long).' % len(key))
    soledad_assert(
        'iv' in kwargs,
        '%s needs an initial value.' % method)
    # AES-256 in CTR mode
    if method == EncryptionMethods.AES_256_CTR:
        return AES(
            key=key, iv=binascii.a2b_base64(kwargs['iv'])).process(data)
    elif method == EncryptionMethods.XSALSA20:
        return XSalsa20(
            key=key, iv=binascii.a2b_base64(kwargs['iv'])).process(data)

    # raise if method is unknown
    raise UnknownEncryptionMethod('Unkwnown method: %s' % method)


def doc_mac_key(doc_id, secret):
    """
    Generate a key for calculating a MAC for a document whose id is
    C{doc_id}.

    The key is derived using HMAC having sha256 as underlying hash
    function. The key used for HMAC is the first MAC_KEY_LENGTH characters
    of Soledad's storage secret. The HMAC message is C{doc_id}.

    :param doc_id: The id of the document.
    :type doc_id: str

    :param secret: soledad secret storage
    :type secret: Soledad.storage_secret

    :return: The key.
    :rtype: str

    :raise NoSymmetricSecret: if no symmetric secret was supplied.
    """
    if secret is None:
        raise NoSymmetricSecret()

    return hmac.new(
        secret[:MAC_KEY_LENGTH],
        doc_id,
        hashlib.sha256).digest()


class SoledadCrypto(object):
    """
    General cryptographic functionality encapsulated in a
    object that can be passed along.
    """
    def __init__(self, soledad):
        """
        Initialize the crypto object.

        :param soledad: A Soledad instance for key lookup.
        :type soledad: leap.soledad.Soledad
        """
        self._soledad = soledad

    def encrypt_sym(self, data, key,
                    method=EncryptionMethods.AES_256_CTR):
        return encrypt_sym(data, key, method)

    def decrypt_sym(self, data, key,
                    method=EncryptionMethods.AES_256_CTR, **kwargs):
        return decrypt_sym(data, key, method, **kwargs)

    def doc_mac_key(self, doc_id, secret):
        return doc_mac_key(doc_id, self.secret)

    def doc_passphrase(self, doc_id):
        """
        Generate a passphrase for symmetric encryption of document's contents.

        The password is derived using HMAC having sha256 as underlying hash
        function. The key used for HMAC are the first
        C{soledad.REMOTE_STORAGE_SECRET_LENGTH} bytes of Soledad's storage
        secret stripped from the first MAC_KEY_LENGTH characters. The HMAC
        message is C{doc_id}.

        :param doc_id: The id of the document that will be encrypted using
            this passphrase.
        :type doc_id: str

        :return: The passphrase.
        :rtype: str

        :raise NoSymmetricSecret: if no symmetric secret was supplied.
        """
        if self.secret is None:
            raise NoSymmetricSecret()
        return hmac.new(
            self.secret[
                MAC_KEY_LENGTH:
                self._soledad.REMOTE_STORAGE_SECRET_LENGTH],
            doc_id,
            hashlib.sha256).digest()

    #
    # secret setters/getters
    #

    def _get_secret(self):
        return self._soledad.storage_secret

    secret = property(
        _get_secret, doc='The secret used for symmetric encryption')


#
# Crypto utilities for a SoledadDocument.
#

def mac_doc(doc_id, doc_rev, ciphertext, mac_method, secret):
    """
    Calculate a MAC for C{doc} using C{ciphertext}.

    Current MAC method used is HMAC, with the following parameters:

        * key: sha256(storage_secret, doc_id)
        * msg: doc_id + doc_rev + ciphertext
        * digestmod: sha256

    :param doc_id: The id of the document.
    :type doc_id: str
    :param doc_rev: The revision of the document.
    :type doc_rev: str
    :param ciphertext: The content of the document.
    :type ciphertext: str
    :param mac_method: The MAC method to use.
    :type mac_method: str
    :param secret: soledad secret
    :type secret: Soledad.secret_storage

    :return: The calculated MAC.
    :rtype: str
    """
    if mac_method == MacMethods.HMAC:
        return hmac.new(
            doc_mac_key(doc_id, secret),
            str(doc_id) + str(doc_rev) + ciphertext,
            hashlib.sha256).digest()
    # raise if we do not know how to handle this MAC method
    raise UnknownMacMethod('Unknown MAC method: %s.' % mac_method)


def encrypt_doc(crypto, doc):
    """
    Wrapper around encrypt_docstr that accepts a crypto object and the document
    as arguments.

    :param crypto: a soledad crypto object.
    :type crypto: SoledadCrypto
    :param doc: the document.
    :type doc: SoledadDocument
    """
    key = crypto.doc_passphrase(doc.doc_id)
    secret = crypto.secret

    return encrypt_docstr(
        doc.get_json(), doc.doc_id, doc.rev, key, secret)


def encrypt_docstr(docstr, doc_id, doc_rev, key, secret):
    """
    Encrypt C{doc}'s content.

    Encrypt doc's contents using AES-256 CTR mode and return a valid JSON
    string representing the following:

        {
            ENC_JSON_KEY: '<encrypted doc JSON string>',
            ENC_SCHEME_KEY: 'symkey',
            ENC_METHOD_KEY: EncryptionMethods.AES_256_CTR,
            ENC_IV_KEY: '<the initial value used to encrypt>',
            MAC_KEY: '<mac>'
            MAC_METHOD_KEY: 'hmac'
        }

    :param docstr: A representation of the document to be encrypted.
    :type docstr: str or unicode.

    :param doc_id: The document id.
    :type doc_id: str

    :param doc_rev: The document revision.
    :type doc_rev: str

    :param key: The key used to encrypt ``data`` (must be 256 bits long).
    :type key: str

    :param secret: The Soledad secret (used for MAC auth).
    :type secret: str

    :return: The JSON serialization of the dict representing the encrypted
             content.
    :rtype: str
    """
    # encrypt content using AES-256 CTR mode
    iv, ciphertext = encrypt_sym(
        str(docstr),  # encryption/decryption routines expect str
        key, method=EncryptionMethods.AES_256_CTR)
    # Return a representation for the encrypted content. In the following, we
    # convert binary data to hexadecimal representation so the JSON
    # serialization does not complain about what it tries to serialize.
    hex_ciphertext = binascii.b2a_hex(ciphertext)
    return json.dumps({
        ENC_JSON_KEY: hex_ciphertext,
        ENC_SCHEME_KEY: EncryptionSchemes.SYMKEY,
        ENC_METHOD_KEY: EncryptionMethods.AES_256_CTR,
        ENC_IV_KEY: iv,
        MAC_KEY: binascii.b2a_hex(mac_doc(  # store the mac as hex.
            doc_id, doc_rev, ciphertext,
            MacMethods.HMAC, secret)),
        MAC_METHOD_KEY: MacMethods.HMAC,
    })


def decrypt_doc(crypto, doc):
    """
    Wrapper around decrypt_doc_dict that accepts a crypto object and the
    document as arguments.

    :param crypto: a soledad crypto object.
    :type crypto: SoledadCrypto
    :param doc: the document.
    :type doc: SoledadDocument

    :return: json string with the decrypted document
    :rtype: str
    """
    key = crypto.doc_passphrase(doc.doc_id)
    secret = crypto.secret
    return decrypt_doc_dict(doc.content, doc.doc_id, doc.rev, key, secret)


def decrypt_doc_dict(doc_dict, doc_id, doc_rev, key, secret):
    """
    Decrypt C{doc}'s content.

    Return the JSON string representation of the document's decrypted content.

    The passed doc_dict argument should have the following structure:

        {
            ENC_JSON_KEY: '<enc_blob>',
            ENC_SCHEME_KEY: '<enc_scheme>',
            ENC_METHOD_KEY: '<enc_method>',
            ENC_IV_KEY: '<initial value used to encrypt>',  # (optional)
            MAC_KEY: '<mac>'
            MAC_METHOD_KEY: 'hmac'
        }

    C{enc_blob} is the encryption of the JSON serialization of the document's
    content. For now Soledad just deals with documents whose C{enc_scheme} is
    EncryptionSchemes.SYMKEY and C{enc_method} is
    EncryptionMethods.AES_256_CTR.

    :param doc_dict: The content of the document to be decrypted.
    :type doc_dict: dict

    :param doc_id: The document id.
    :type doc_id: str

    :param doc_rev: The document revision.
    :type doc_rev: str

    :param key: The key used to encrypt ``data`` (must be 256 bits long).
    :type key: str

    :param secret:
    :type secret:

    :return: The JSON serialization of the decrypted content.
    :rtype: str
    """
    soledad_assert(ENC_JSON_KEY in doc_dict)
    soledad_assert(ENC_SCHEME_KEY in doc_dict)
    soledad_assert(ENC_METHOD_KEY in doc_dict)
    soledad_assert(MAC_KEY in doc_dict)
    soledad_assert(MAC_METHOD_KEY in doc_dict)

    # verify MAC
    ciphertext = binascii.a2b_hex(  # content is stored as hex.
        doc_dict[ENC_JSON_KEY])
    mac = mac_doc(
        doc_id, doc_rev,
        ciphertext,
        doc_dict[MAC_METHOD_KEY], secret)
    # we compare mac's hashes to avoid possible timing attacks that might
    # exploit python's builtin comparison operator behaviour, which fails
    # immediatelly when non-matching bytes are found.
    doc_mac_hash = hashlib.sha256(
        binascii.a2b_hex(  # the mac is stored as hex
            doc_dict[MAC_KEY])).digest()
    calculated_mac_hash = hashlib.sha256(mac).digest()

    if doc_mac_hash != calculated_mac_hash:
        logger.warning("Wrong MAC while decrypting doc...")
        raise WrongMac('Could not authenticate document\'s contents.')
    # decrypt doc's content
    enc_scheme = doc_dict[ENC_SCHEME_KEY]
    plainjson = None
    if enc_scheme == EncryptionSchemes.SYMKEY:
        enc_method = doc_dict[ENC_METHOD_KEY]
        if enc_method == EncryptionMethods.AES_256_CTR:
            soledad_assert(ENC_IV_KEY in doc_dict)
            plainjson = decrypt_sym(
                ciphertext, key,
                method=enc_method,
                iv=doc_dict[ENC_IV_KEY])
        else:
            raise UnknownEncryptionMethod(enc_method)
    else:
        raise UnknownEncryptionScheme(enc_scheme)

    return plainjson


def is_symmetrically_encrypted(doc):
    """
    Return True if the document was symmetrically encrypted.

    :param doc: The document to check.
    :type doc: SoledadDocument

    :rtype: bool
    """
    if doc.content and ENC_SCHEME_KEY in doc.content:
        if doc.content[ENC_SCHEME_KEY] == EncryptionSchemes.SYMKEY:
            return True
    return False


#
# Encrypt/decrypt pools of workers
#

class SyncEncryptDecryptPool(object):
    """
    Base class for encrypter/decrypter pools.
    """
    WORKERS = 5

    def __init__(self, crypto, sync_db, write_lock):
        """
        Initialize the pool of encryption-workers.

        :param crypto: A SoledadCryto instance to perform the encryption.
        :type crypto: leap.soledad.crypto.SoledadCrypto

        :param sync_db: a database connection handle
        :type sync_db: handle

        :param write_lock: a write lock for controlling concurrent access
                           to the sync_db
        :type write_lock: threading.Lock
        """
        self._pool = multiprocessing.Pool(self.WORKERS)
        self._crypto = crypto
        self._sync_db = sync_db
        self._sync_db_write_lock = write_lock

    def close(self):
        """
        Cleanly close the pool of workers.
        """
        logger.debug("Closing %s" % (self.__class__.__name__,))
        self._pool.close()
        try:
            self._pool.join()
        except Exception:
            pass

    def terminate(self):
        """
        Terminate the pool of workers.
        """
        logger.debug("Terminating %s" % (self.__class__.__name__,))
        self._pool.terminate()


def encrypt_doc_task(doc_id, doc_rev, content, key, secret):
    """
    Encrypt the content of the given document.

    :param doc_id: The document id.
    :type doc_id: str
    :param doc_rev: The document revision.
    :type doc_rev: str
    :param content: The serialized content of the document.
    :type content: str
    :param key: The encryption key.
    :type key: str
    :param secret: The Soledad secret (used for MAC auth).
    :type secret: str

    :return: A tuple containing the doc id, revision and encrypted content.
    :rtype: tuple(str, str, str)
    """
    encrypted_content = encrypt_docstr(
        content, doc_id, doc_rev, key, secret)
    return doc_id, doc_rev, encrypted_content


class SyncEncrypterPool(SyncEncryptDecryptPool):
    """
    Pool of workers that spawn subprocesses to execute the symmetric encryption
    of documents to be synced.
    """
    # TODO implement throttling to reduce cpu usage??
    WORKERS = 5
    TABLE_NAME = "docs_tosync"
    FIELD_NAMES = "doc_id, rev, content"

    def encrypt_doc(self, doc, workers=True):
        """
        Symmetrically encrypt a document.

        :param doc: The document with contents to be encrypted.
        :type doc: SoledadDocument

        :param workers: Whether to defer the decryption to the multiprocess
                        pool of workers. Useful for debugging purposes.
        :type workers: bool
        """
        soledad_assert(self._crypto is not None, "need a crypto object")
        docstr = doc.get_json()
        key = self._crypto.doc_passphrase(doc.doc_id)
        secret = self._crypto.secret
        args = doc.doc_id, doc.rev, docstr, key, secret

        try:
            if workers:
                res = self._pool.apply_async(
                    encrypt_doc_task, args,
                    callback=self.encrypt_doc_cb)
            else:
                # encrypt inline
                res = encrypt_doc_task(*args)
                self.encrypt_doc_cb(res)

        except Exception as exc:
            logger.exception(exc)

    def encrypt_doc_cb(self, result):
        """
        Insert results of encryption routine into the local sync database.

        :param result: A tuple containing the doc id, revision and encrypted
                       content.
        :type result: tuple(str, str, str)
        """
        doc_id, doc_rev, content = result
        self.insert_encrypted_local_doc(doc_id, doc_rev, content)

    def insert_encrypted_local_doc(self, doc_id, doc_rev, content):
        """
        Insert the contents of the encrypted doc into the local sync
        database.

        :param doc_id: The document id.
        :type doc_id: str
        :param doc_rev: The document revision.
        :type doc_rev: str
        :param content: The serialized content of the document.
        :type content: str
        :param content: The encrypted document.
        :type content: str
        """
        sql_del = "DELETE FROM '%s' WHERE doc_id=?" % (self.TABLE_NAME,)
        sql_ins = "INSERT INTO '%s' VALUES (?, ?, ?)" % (self.TABLE_NAME,)

        con = self._sync_db
        with self._sync_db_write_lock:
            con.execute(sql_del, (doc_id, ))
            con.execute(sql_ins, (doc_id, doc_rev, content))


def decrypt_doc_task(doc_id, doc_rev, content, gen, trans_id, key, secret):
    """
    Decrypt the content of the given document.

    :param doc_id: The document id.
    :type doc_id: str
    :param doc_rev: The document revision.
    :type doc_rev: str
    :param content: The encrypted content of the document.
    :type content: str
    :param gen: The generation corresponding to the modification of that
                document.
    :type gen: int
    :param trans_id: The transaction id corresponding to the modification of
                     that document.
    :type trans_id: str
    :param key: The encryption key.
    :type key: str
    :param secret: The Soledad secret (used for MAC auth).
    :type secret: str

    :return: A tuple containing the doc id, revision and encrypted content.
    :rtype: tuple(str, str, str)
    """
    decrypted_content = decrypt_doc_dict(
        content, doc_id, doc_rev, key, secret)
    return doc_id, doc_rev, decrypted_content, gen, trans_id


class SyncDecrypterPool(SyncEncryptDecryptPool):
    """
    Pool of workers that spawn subprocesses to execute the symmetric decryption
    of documents that were received.

    The decryption of the received documents is done in two steps:

        1. All the encrypted docs are collected, together with their generation
           and transaction-id
        2. The docs are enqueued for decryption. When completed, they are
           inserted following the generation order.
    """
    # TODO implement throttling to reduce cpu usage??
    TABLE_NAME = "docs_received"
    FIELD_NAMES = "doc_id, rev, content, gen, trans_id, encrypted"

    write_encrypted_lock = threading.Lock()

    def __init__(self, *args, **kwargs):
        """
        Initialize the decrypter pool, and setup a dict for putting the
        results of the decrypted docs until they are picked by the insert
        routine that gets them in order.

        :param insert_doc_cb: A callback for inserting received documents from
                              target. If not overriden, this will call u1db
                              insert_doc_from_target in synchronizer, which
                              implements the TAKE OTHER semantics.
        :type insert_doc_cb: function
        :param last_known_generation: Target's last known generation.
        :type last_known_generation: int
        """
        self._insert_doc_cb = kwargs.pop("insert_doc_cb")
        SyncEncryptDecryptPool.__init__(self, *args, **kwargs)
        self.source_replica_uid = None

    def set_source_replica_uid(self, source_replica_uid):
        """
        Set the source replica uid for this decrypter pool instance.

        :param source_replica_uid: The uid of the source replica.
        :type source_replica_uid: str
        """
        self.source_replica_uid = source_replica_uid

    def insert_encrypted_received_doc(self, doc_id, doc_rev, content,
                                      gen, trans_id):
        """
        Insert a received message with encrypted content, to be decrypted later
        on.

        :param doc_id: The Document ID.
        :type doc_id: str
        :param doc_rev: The Document Revision
        :param doc_rev: str
        :param content: the Content of the document
        :type content: str
        :param gen: the Document Generation
        :type gen: int
        :param trans_id: Transaction ID
        :type trans_id: str
        """
        docstr = json.dumps(content)
        sql_del = "DELETE FROM '%s' WHERE doc_id=?" % (self.TABLE_NAME,)
        sql_ins = "INSERT INTO '%s' VALUES (?, ?, ?, ?, ?, ?)" % (
            self.TABLE_NAME,)

        con = self._sync_db
        with self._sync_db_write_lock:
            con.execute(sql_del, (doc_id, ))
            con.execute(
                sql_ins,
                (doc_id, doc_rev, docstr, gen, trans_id, 1))

    def insert_received_doc(self, doc_id, doc_rev, content, gen, trans_id):
        """
        Insert a document that is not symmetrically encrypted.
        We store it in the staging area (the decrypted_docs dictionary) to be
        picked up in order as the preceding documents are decrypted.

        :param doc_id: The Document ID.
        :type doc_id: str
        :param doc_rev: The Document Revision
        :param doc_rev: str
        :param content: the Content of the document
        :type content: str
        :param gen: the Document Generation
        :type gen: int
        :param trans_id: Transaction ID
        :type trans_id: str
        """
        if not isinstance(content, str):
            content = json.dumps(content)
        sql_del = "DELETE FROM '%s' WHERE doc_id=?" % (
            self.TABLE_NAME,)
        sql_ins = "INSERT INTO '%s' VALUES (?, ?, ?, ?, ?, ?)" % (
            self.TABLE_NAME,)
        con = self._sync_db
        with self._sync_db_write_lock:
            con.execute(sql_del, (doc_id,))
            con.execute(
                sql_ins,
                (doc_id, doc_rev, content, gen, trans_id, 0))

    def delete_received_doc(self, doc_id, doc_rev):
        """
        Delete a received doc after it was inserted into the local db.

        :param doc_id: Document ID.
        :type doc_id: str
        :param doc_rev: Document revision.
        :type doc_rev: str
        """
        sql_del = "DELETE FROM '%s' WHERE doc_id=? AND rev=?" % (
            self.TABLE_NAME,)
        con = self._sync_db
        with self._sync_db_write_lock:
            con.execute(sql_del, (doc_id, doc_rev))

    def decrypt_doc(self, doc_id, rev, content, gen, trans_id,
                    source_replica_uid, workers=True):
        """
        Symmetrically decrypt a document.

        :param doc_id: The ID for the document with contents to be encrypted.
        :type doc: str
        :param rev: The revision of the document.
        :type rev: str
        :param content: The serialized content of the document.
        :type content: str
        :param gen: The generation corresponding to the modification of that
                    document.
        :type gen: int
        :param trans_id: The transaction id corresponding to the modification
                         of that document.
        :type trans_id: str
        :param source_replica_uid:
        :type source_replica_uid: str

        :param workers: Whether to defer the decryption to the multiprocess
                        pool of workers. Useful for debugging purposes.
        :type workers: bool
        """
        self.source_replica_uid = source_replica_uid

        # insert_doc_cb is a proxy object that gets updated with the right
        # insert function only when the sync_target invokes the sync_exchange
        # method. so, if we don't still have a non-empty callback, we refuse
        # to proceed.
        if sameProxiedObjects(self._insert_doc_cb.get(source_replica_uid),
                              None):
            logger.debug("Sync decrypter pool: no insert_doc_cb() yet.")
            return

        soledad_assert(self._crypto is not None, "need a crypto object")

        if len(content) == 0:
            # not encrypted payload
            return

        try:
            content = json.loads(content)
        except TypeError:
            logger.warning("Wrong type while decoding json: %s" % repr(docstr))
            return

        key = self._crypto.doc_passphrase(doc_id)
        secret = self._crypto.secret
        args = doc_id, rev, content, gen, trans_id, key, secret

        try:
            if workers:
                # Ouch. This is sent to the workers asynchronously, so
                # we have no way of logging errors. We'd have to inspect
                # lingering results by querying successful / get() over them...
                # Or move the heck out of it to twisted.
                res = self._pool.apply_async(
                    decrypt_doc_task, args,
                    callback=self.decrypt_doc_cb)
            else:
                # decrypt inline
                res = decrypt_doc_task(*args)
                self.decrypt_doc_cb(res)

        except Exception as exc:
            logger.exception(exc)

    def decrypt_doc_cb(self, result):
        """
        Store the decryption result in the sync db from where it will later be
        picked by process_decrypted.

        :param result: A tuple containing the doc id, revision and encrypted
        content.
        :type result: tuple(str, str, str)
        """
        doc_id, rev, content, gen, trans_id = result
        logger.debug("Sync decrypter pool: decrypted doc %s: %s %s %s"
                     % (doc_id, rev, gen, trans_id))
        self.insert_received_doc(doc_id, rev, content, gen, trans_id)

    def get_docs_by_generation(self, encrypted=None):
        """
        Get all documents in the received table from the sync db,
        ordered by generation.

        :param encrypted: If not None, only return documents with encrypted
                          field equal to given parameter.
        :type encrypted: bool

        :return: list of doc_id, rev, generation, gen, trans_id
        :rtype: list
        """
        sql = "SELECT doc_id, rev, content, gen, trans_id, encrypted FROM %s" \
              % self.TABLE_NAME
        if encrypted is not None:
            sql += " WHERE encrypted = %d" % int(encrypted)
        sql += " ORDER BY gen ASC"
        docs = self._sync_db.select(sql)
        return docs

    def get_insertable_docs_by_gen(self):
        """
        Return a list of documents ready to be inserted.
        """
        all_docs = self.get_docs_by_generation()
        decrypted_docs = self.get_docs_by_generation(encrypted=False)
        insertable = []
        for doc_id, rev, content, gen, trans_id, encrypted in all_docs:
            next_decrypted = decrypted_docs.next()
            if doc_id == next_decrypted[0]:
                insertable.append((doc_id, rev, content, gen, trans_id))
            else:
                break
        return insertable

    def count_docs_in_sync_db(self, encrypted=None):
        """
        Count how many documents we have in the table for received docs.

        :param encrypted: If not None, return count of documents with
                          encrypted field equal to given parameter.
        :type encrypted: bool

        :return: The count of documents.
        :rtype: int
        """
        if self._sync_db is None:
            logger.warning("cannot return count with null sync_db")
            return
        sql = "SELECT COUNT(*) FROM %s" % (self.TABLE_NAME,)
        if encrypted is not None:
            sql += " WHERE encrypted = %d" % int(encrypted)
        res = self._sync_db.select(sql)
        if res is not None:
            val = res.next()
            return val[0]
        else:
            return 0

    def decrypt_received_docs(self):
        """
        Get all the encrypted documents from the sync database and dispatch a
        decrypt worker to decrypt each one of them.
        """
        docs_by_generation = self.get_docs_by_generation(encrypted=True)
        for doc_id, rev, content, gen, trans_id, _ \
                in filter(None, docs_by_generation):
            self.decrypt_doc(
                doc_id, rev, content, gen, trans_id, self.source_replica_uid)

    def process_decrypted(self):
        """
        Process the already decrypted documents, and insert as many documents
        as can be taken from the expected order without finding a gap.

        :return: Whether we have processed all the pending docs.
        :rtype: bool
        """
        # Acquire the lock to avoid processing while we're still
        # getting data from the syncing stream, to avoid InvalidGeneration
        # problems.
        with self.write_encrypted_lock:
            for doc_fields in self.get_insertable_docs_by_gen():
                self.insert_decrypted_local_doc(*doc_fields)
        remaining = self.count_docs_in_sync_db()
        return remaining == 0

    def insert_decrypted_local_doc(self, doc_id, doc_rev, content,
                                   gen, trans_id):
        """
        Insert the decrypted document into the local sqlcipher database.
        Makes use of the passed callback `return_doc_cb` passed to the caller
        by u1db sync.

        :param doc_id: The document id.
        :type doc_id: str
        :param doc_rev: The document revision.
        :type doc_rev: str
        :param content: The serialized content of the document.
        :type content: str
        :param gen: The generation corresponding to the modification of that
                    document.
        :type gen: int
        :param trans_id: The transaction id corresponding to the modification
                         of that document.
        :type trans_id: str
        """
        # could pass source_replica in params for callback chain
        insert_fun = self._insert_doc_cb[self.source_replica_uid]
        logger.debug("Sync decrypter pool: inserting doc in local db: " \
                     "%s:%s %s" % (doc_id, doc_rev, gen))
        try:
            # convert deleted documents to avoid error on document creation
            if content == 'null':
                content = None
            doc = SoledadDocument(doc_id, doc_rev, content)
            gen = int(gen)
            insert_fun(doc, gen, trans_id)
        except Exception as exc:
            logger.error("Sync decrypter pool: error while inserting "
                         "decrypted doc into local db.")
            logger.exception(exc)

        else:
            # If no errors found, remove it from the received database.
            self.delete_received_doc(doc_id, doc_rev)
