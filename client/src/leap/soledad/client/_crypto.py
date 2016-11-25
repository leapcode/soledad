# -*- coding: utf-8 -*-
# _crypto.py
# Copyright (C) 2016 LEAP Encryption Access Project
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
Cryptographic operations for the soledad client
"""

import binascii
import base64
import hashlib
import hmac
import os
import struct
import time

from io import BytesIO
from collections import namedtuple

import six

from twisted.internet import defer
from twisted.internet import interfaces
from twisted.logger import Logger
from twisted.web.client import FileBodyProducer

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends.multibackend import MultiBackend
from cryptography.hazmat.backends.openssl.backend \
    import Backend as OpenSSLBackend

from zope.interface import implements


log = Logger()

MAC_KEY_LENGTH = 64

crypto_backend = MultiBackend([OpenSSLBackend()])


class ENC_SCHEME:
    symkey = 1


class ENC_METHOD:
    aes_256_ctr = 1


class EncryptionDecryptionError(Exception):
    pass


class InvalidBlob(Exception):
    pass


docinfo = namedtuple('docinfo', 'doc_id rev')


class SoledadCrypto(object):
    """
    This class provides convenient methods for document encryption and
    decryption using BlobEncryptor and BlobDecryptor classes.
    """
    def __init__(self, secret):
        """
        Initialize the crypto object.

        :param secret: The Soledad remote storage secret.
        :type secret: str
        """
        self.secret = secret

    def encrypt_doc(self, doc):
        """
        Creates and configures a BlobEncryptor, asking it to start encryption
        and wrapping the result as a simple JSON string with a "raw" key.

        :param doc: the document to be encrypted.
        :type doc: SoledadDocument
        :return: A deferred whose callback will be invoked with a JSON string
            containing the ciphertext as the value of "raw" key.
        :rtype: twisted.internet.defer.Deferred
        """

        def put_raw(blob):
            raw = blob.getvalue()
            return '{"raw": "' + raw + '"}'

        content = BytesIO()
        content.write(str(doc.get_json()))
        info = docinfo(doc.doc_id, doc.rev)
        del doc
        encryptor = BlobEncryptor(info, content, secret=self.secret)
        d = encryptor.encrypt()
        d.addCallback(put_raw)
        return d

    def decrypt_doc(self, doc):
        """
        Creates and configures a BlobDecryptor, asking it decrypt and returning
        the decrypted cleartext content from the encrypted document.

        :param doc: the document to be decrypted.
        :type doc: SoledadDocument
        :return: The decrypted cleartext content of the document.
        :rtype: str
        """
        info = docinfo(doc.doc_id, doc.rev)
        ciphertext = BytesIO()
        payload = doc.content['raw']
        del doc
        ciphertext.write(str(payload))
        decryptor = BlobDecryptor(info, ciphertext, secret=self.secret)
        buf = decryptor.decrypt()
        return buf.getvalue()


def encrypt_sym(data, key):
    """
    Encrypt data using AES-256 cipher in CTR mode.

    :param data: The data to be encrypted.
    :type data: str
    :param key: The key used to encrypt data (must be 256 bits long).
    :type key: str

    :return: A tuple with the initialization vector and the ciphertext, both
        encoded as base64.
    :rtype: (str, str)
    """
    encryptor = AESEncryptor(key)
    encryptor.write(data)
    encryptor.end()
    ciphertext = encryptor.fd.getvalue()
    return base64.b64encode(encryptor.iv), ciphertext


def decrypt_sym(data, key, iv):
    """
    Decrypt data using AES-256 cipher in CTR mode.

    :param data: The data to be decrypted.
    :type data: str
    :param key: The symmetric key used to decrypt data (must be 256 bits
                long).
    :type key: str
    :param iv: The base64 encoded initialization vector.
    :type iv: str

    :return: The decrypted data.
    :rtype: str
    """
    _iv = base64.b64decode(str(iv))
    decryptor = AESDecryptor(key, _iv)
    decryptor.write(data)
    decryptor.end()
    plaintext = decryptor.fd.getvalue()
    return plaintext


class BlobEncryptor(object):
    """
    Produces encrypted data from the cleartext data associated with a given
    SoledadDocument using AES-256 cipher in CTR mode, together with a
    HMAC-SHA512 Message Authentication Code.
    The production happens using a Twisted's FileBodyProducer, which uses a
    Cooperator to schedule calls and can be paused/resumed. Each call takes at
    most 65536 bytes from the input.
    Both the production input and output are file descriptors, so they can be
    applied to a stream of data.
    """
    def __init__(self, doc_info, content_fd, result=None, secret=None):
        if not secret:
            raise EncryptionDecryptionError('no secret given')

        self.doc_id = doc_info.doc_id
        self.rev = doc_info.rev

        content_fd.seek(0)
        self._producer = FileBodyProducer(content_fd, readSize=2**16)
        self._content_fd = content_fd

        self._preamble = BytesIO()
        self.result = result or BytesIO()

        sym_key = _get_sym_key_for_doc(doc_info.doc_id, secret)
        mac_key = _get_mac_key_for_doc(doc_info.doc_id, secret)

        self._aes_fd = BytesIO()
        self._aes = AESEncryptor(sym_key, self._aes_fd)
        self._hmac = HMACWriter(mac_key)
        self._write_preamble()

        self._crypter = VerifiedEncrypter(self._aes, self._hmac)

    @property
    def iv(self):
        return self._aes.iv

    def encrypt(self):
        """
        Starts producing encrypted data from the cleartext data.

        :return: A deferred which will be fired when encryption ends and whose
            callback will be invoked with the resulting ciphertext.
        :rtype: twisted.internet.defer.Deferred
        """
        d = self._producer.startProducing(self._crypter)
        d.addCallback(self._end_crypto_stream)
        return d

    def encrypt_whole(self):
        """
        Encrypts the input data at once and returns the resulting ciphertext
        wrapped into a JSON string under the "raw" key.

        :return: The resulting ciphertext JSON string.
        :rtype: str
        """
        self._crypter.write(self._content_fd.getvalue())
        self._end_crypto_stream(None)
        return '{"raw":"' + self.result.getvalue() + '"}'

    def _write_preamble(self):

        def write(data):
            self._preamble.write(data)
            self._hmac.write(data)

        current_time = int(time.time())

        write(b'\x80')
        write(struct.pack(
            'Qbb',
            current_time,
            ENC_SCHEME.symkey,
            ENC_METHOD.aes_256_ctr))
        write(self.iv)
        write(str(self.doc_id))
        write(str(self.rev))

    def _end_crypto_stream(self, ignored):
        self._aes.end()
        self._hmac.end()
        self._content_fd.close()

        preamble = self._preamble.getvalue()
        encrypted = self._aes_fd.getvalue()
        hmac = self._hmac.result.getvalue()

        self.result.write(
            base64.urlsafe_b64encode(preamble + encrypted + hmac))
        self._preamble.close()
        self._aes_fd.close()
        self._hmac.result.close()
        self.result.seek(0)
        return defer.succeed(self.result)


class BlobDecryptor(object):
    """
    Decrypts an encrypted blob associated with a given Document.

    Will raise an exception if the blob doesn't have the expected structure, or
    if the HMAC doesn't verify.
    """

    def __init__(self, doc_info, ciphertext_fd, result=None,
                 secret=None):
        self.doc_id = doc_info.doc_id
        self.rev = doc_info.rev

        self.ciphertext = ciphertext_fd

        self.sym_key = _get_sym_key_for_doc(doc_info.doc_id, secret)
        self.mac_key = _get_mac_key_for_doc(doc_info.doc_id, secret)

        self.result = result or BytesIO()

    def decrypt(self):
        try:
            data = base64.urlsafe_b64decode(self.ciphertext.getvalue())
        except (TypeError, binascii.Error):
            raise InvalidBlob
        self.ciphertext.close()

        if not data or six.indexbytes(data, 0) != 0x80:
            raise InvalidBlob
        try:
            ts, sch, meth = struct.unpack("Qbb", data[1:11])
        except struct.error:
            raise InvalidBlob

        # TODO check timestamp
        if sch != ENC_SCHEME.symkey:
            raise InvalidBlob('invalid scheme')
        # TODO should adapt the assymetric-gpg too, rigth?
        if meth != ENC_METHOD.aes_256_ctr:
            raise InvalidBlob('invalid encryption scheme')

        iv = data[11:27]
        docidlen = len(self.doc_id)
        ciph_idx = 26 + docidlen
        revlen = len(self.rev)
        rev_idx = ciph_idx + 1 + revlen
        rev = data[ciph_idx + 1:rev_idx]

        if rev != self.rev:
            raise InvalidBlob('invalid revision')

        ciphertext = data[rev_idx:-64]
        hmac = data[-64:]

        h = HMAC(self.mac_key, hashes.SHA512(), backend=crypto_backend)
        h.update(data[:-64])
        try:
            h.verify(hmac)
        except InvalidSignature:
            raise InvalidBlob('HMAC could not be verifed')

        decryptor = _get_aes_ctr_cipher(self.sym_key, iv).decryptor()

        # TODO pass chunks, streaming, instead
        # Use AESDecryptor below

        self.result.write(decryptor.update(ciphertext))
        self.result.write(decryptor.finalize())
        return self.result


class AESEncryptor(object):
    """
    A Twisted's Consumer implementation that takes an input file descriptor and
    applies AES-256 cipher in CTR mode.
    """
    implements(interfaces.IConsumer)

    def __init__(self, key, fd=None):
        if len(key) != 32:
            raise EncryptionDecryptionError('key is not 256 bits')
        self.iv = os.urandom(16)

        cipher = _get_aes_ctr_cipher(key, self.iv)
        self.encryptor = cipher.encryptor()

        self.fd = fd or BytesIO()

        self.done = False

    def write(self, data):
        encrypted = self.encryptor.update(data)
        self.fd.write(encrypted)
        return encrypted

    def end(self):
        if not self.done:
            self.fd.write(self.encryptor.finalize())
        self.done = True


class HMACWriter(object):
    """
    A Twisted's Consumer implementation that takes an input file descriptor and
    produces a HMAC-SHA512 Message Authentication Code.
    """
    implements(interfaces.IConsumer)
    hashtype = 'sha512'

    def __init__(self, key):
        self._hmac = hmac.new(key, '', getattr(hashlib, self.hashtype))
        self.result = BytesIO('')

    def write(self, data):
        self._hmac.update(data)

    def end(self):
        self.result.write(self._hmac.digest())


class VerifiedEncrypter(object):
    """
    A Twisted's Consumer implementation combining AESEncryptor and HMACWriter.
    It directs the resulting ciphertext into HMAC-SHA512 processing.
    """
    implements(interfaces.IConsumer)

    def __init__(self, crypter, hmac):
        self.crypter = crypter
        self.hmac = hmac

    def write(self, data):
        enc_chunk = self.crypter.write(data)
        self.hmac.write(enc_chunk)


class AESDecryptor(object):
    """
    A Twisted's Consumer implementation that consumes data encrypted with
    AES-256 in CTR mode from a file descriptor and generates decrypted data.
    """
    implements(interfaces.IConsumer)

    def __init__(self, key, iv, fd=None):
        iv = iv or os.urandom(16)
        if len(key) != 32:
            raise EncryptionDecryptionError('key is not 256 bits')
        if len(iv) != 16:
            raise EncryptionDecryptionError('iv is not 128 bits')

        cipher = _get_aes_ctr_cipher(key, iv)
        self.decryptor = cipher.decryptor()

        self.fd = fd or BytesIO()
        self.done = False
        self.deferred = defer.Deferred()

    def write(self, data):
        decrypted = self.decryptor.update(data)
        self.fd.write(decrypted)
        return decrypted

    def end(self):
        if not self.done:
            self.decryptor.finalize()
            self.deferred.callback(self.fd)
        self.done = True


def is_symmetrically_encrypted(doc):
    """
    Return True if the document was symmetrically encrypted.

    :param doc: The document to check.
    :type doc: SoledadDocument

    :rtype: bool
    """
    payload = doc.content
    if not payload or 'raw' not in payload:
        return False
    payload = str(payload['raw'])
    if len(payload) < 16:
        return False
    header = base64.urlsafe_b64decode(payload[:18] + '==')
    if six.indexbytes(header, 0) != 0x80:
        return False
    ts, sch, meth = struct.unpack('Qbb', header[1:11])
    return sch == ENC_SCHEME.symkey and meth == ENC_METHOD.aes_256_ctr


# utils


def _hmac_sha256(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()


def _get_mac_key_for_doc(doc_id, secret):
    key = secret[:MAC_KEY_LENGTH]
    return _hmac_sha256(key, doc_id)


def _get_sym_key_for_doc(doc_id, secret):
    key = secret[MAC_KEY_LENGTH:]
    return _hmac_sha256(key, doc_id)


def _get_aes_ctr_cipher(key, iv):
    return Cipher(algorithms.AES(key), modes.CTR(iv), backend=crypto_backend)
