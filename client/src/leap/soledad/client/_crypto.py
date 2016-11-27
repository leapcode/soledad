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
import re
import struct
import time

from io import BytesIO
from itertools import imap
from collections import namedtuple

import six

from twisted.internet import defer
from twisted.internet import interfaces
from twisted.web.client import FileBodyProducer

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends.multibackend import MultiBackend
from cryptography.hazmat.backends.openssl.backend \
    import Backend as OpenSSLBackend

from zope.interface import implements


MAC_KEY_LENGTH = 64

CRYPTO_BACKEND = MultiBackend([OpenSSLBackend()])

PACMAN = struct.Struct('cQbb16s255p255p')


ENC_SCHEME = namedtuple('SCHEME', 'symkey')(1)
ENC_METHOD = namedtuple('METHOD', 'aes_256_ctr')(1)
DocInfo = namedtuple('DocInfo', 'doc_id rev')


class EncryptionDecryptionError(Exception):
    pass


class InvalidBlob(Exception):
    pass


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
        info = DocInfo(doc.doc_id, doc.rev)
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
        info = DocInfo(doc.doc_id, doc.rev)
        ciphertext = BytesIO()
        payload = doc.content['raw']
        del doc
        ciphertext.write(str(payload))
        decryptor = BlobDecryptor(info, ciphertext, secret=self.secret)
        return decryptor.decrypt()


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
    encryptor = AESConsumer(key)
    encryptor.write(data)
    encryptor.end()
    ciphertext = encryptor.buffer.getvalue()
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
    decryptor = AESConsumer(key, _iv, operation=AESConsumer.decrypt)
    decryptor.write(data)
    decryptor.end()
    plaintext = decryptor.buffer.getvalue()
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
        _aes = AESConsumer(sym_key, _buffer=self._aes_fd)
        self.__iv = _aes.iv
        self._hmac_writer = HMACWriter(mac_key)
        self._write_preamble()

        self._crypter = PipeableWriter(_aes, self._hmac_writer)

    @property
    def iv(self):
        return self.__iv

    def encrypt(self):
        """
        Starts producing encrypted data from the cleartext data.

        :return: A deferred which will be fired when encryption ends and whose
            callback will be invoked with the resulting ciphertext.
        :rtype: twisted.internet.defer.Deferred
        """
        d = self._producer.startProducing(self._crypter)
        d.addCallback(lambda _: self._end_crypto_stream())
        return d

    def _write_preamble(self):

        def write(data):
            self._preamble.write(data)
            self._hmac_writer.write(data)

        current_time = int(time.time())

        write(PACMAN.pack(
            '\x80',
            current_time,
            ENC_SCHEME.symkey,
            ENC_METHOD.aes_256_ctr,
            self.iv,
            str(self.doc_id),
            str(self.rev)))

    def _end_crypto_stream(self):
        encrypted, content_hmac = self._crypter.end()

        preamble = self._preamble.getvalue()

        self.result.write(
            base64.urlsafe_b64encode(preamble))
        self.result.write(' ')
        self.result.write(
            base64.urlsafe_b64encode(encrypted + content_hmac))
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
        if not secret:
            raise EncryptionDecryptionError('no secret given')

        self.doc_id = doc_info.doc_id
        self.rev = doc_info.rev

        ciphertext_fd, preamble, iv = self._consume_preamble(ciphertext_fd)
        mac_key = _get_mac_key_for_doc(doc_info.doc_id, secret)
        self._current_hmac = BytesIO()
        _hmac_writer = HMACWriter(mac_key, self._current_hmac)
        _hmac_writer.write(preamble)

        self.result = result or BytesIO()
        sym_key = _get_sym_key_for_doc(doc_info.doc_id, secret)
        _aes = AESConsumer(sym_key, iv, self.result,
                           operation=AESConsumer.decrypt)
        self._decrypter = PipeableWriter(_aes, _hmac_writer, pipe=False)

        self._producer = FileBodyProducer(ciphertext_fd, readSize=2**16)

    def _consume_preamble(self, ciphertext_fd):
        ciphertext_fd.seek(0)
        try:
            preamble, ciphertext = _split(ciphertext_fd.getvalue())
            self.doc_hmac, ciphertext = ciphertext[-64:], ciphertext[:-64]
        except (TypeError, binascii.Error):
            raise InvalidBlob
        ciphertext_fd.close()

        if len(preamble) != PACMAN.size:
            raise InvalidBlob

        try:
            unpacked_data = PACMAN.unpack(preamble)
            pad, ts, sch, meth, iv, doc_id, rev = unpacked_data
        except struct.error:
            raise InvalidBlob

        if pad != '\x80':
            raise InvalidBlob
        # TODO check timestamp
        if sch != ENC_SCHEME.symkey:
            raise InvalidBlob('invalid scheme')
        # TODO should adapt the assymetric-gpg too, rigth?
        if meth != ENC_METHOD.aes_256_ctr:
            raise InvalidBlob('invalid encryption scheme')
        if rev != self.rev:
            raise InvalidBlob('invalid revision')
        if doc_id != self.doc_id:
            raise InvalidBlob('invalid revision')
        return BytesIO(ciphertext), preamble, iv

    def _check_hmac(self):
        if self._current_hmac.getvalue() != self.doc_hmac:
            raise InvalidBlob('HMAC could not be verifed')

    def _end_stream(self):
        self._decrypter.end()
        self._check_hmac()
        return self.result.getvalue()

    def decrypt(self):
        """
        Starts producing encrypted data from the cleartext data.

        :return: A deferred which will be fired when encryption ends and whose
            callback will be invoked with the resulting ciphertext.
        :rtype: twisted.internet.defer.Deferred
        """
        d = self._producer.startProducing(self._decrypter)
        d.addCallback(lambda _: self._end_stream())
        return d


class HMACWriter(object):
    """
    A Twisted's Consumer implementation that takes an input file descriptor and
    produces a HMAC-SHA512 Message Authentication Code.
    """
    implements(interfaces.IConsumer)
    hashtype = 'sha512'

    def __init__(self, key, result=None):
        self._hmac = hmac.new(key, '', getattr(hashlib, self.hashtype))
        self.result = result or BytesIO('')

    def write(self, data):
        self._hmac.update(data)

    def end(self):
        self.result.write(self._hmac.digest())
        return self.result.getvalue()


class PipeableWriter(object):
    """
    A Twisted's Consumer implementation that flows data into two writers.
    Here we can combine AESEncryptor and HMACWriter.
    It directs the resulting ciphertext into HMAC-SHA512 processing if
    pipe=True or writes the ciphertext to both (fan out, which is the case when
    decrypting).
    """
    implements(interfaces.IConsumer)

    def __init__(self, aes_writer, hmac_writer, pipe=True):
        self.pipe = pipe
        self.aes_writer = aes_writer
        self.hmac_writer = hmac_writer

    def write(self, data):
        enc_chunk = self.aes_writer.write(data)
        if not self.pipe:
            enc_chunk = data
        self.hmac_writer.write(enc_chunk)

    def end(self):
        ciphertext = self.aes_writer.end()
        content_hmac = self.hmac_writer.end()
        return ciphertext, content_hmac


class AESConsumer(object):
    """
    A Twisted's Consumer implementation that takes an input file descriptor and
    applies AES-256 cipher in CTR mode.
    """
    implements(interfaces.IConsumer)
    encrypt = 1
    decrypt = 2

    def __init__(self, key, iv=None, _buffer=None, operation=encrypt):
        if len(key) != 32:
            raise EncryptionDecryptionError('key is not 256 bits')
        self.iv = iv or os.urandom(16)
        self.buffer = _buffer or BytesIO()
        self.deferred = defer.Deferred()
        self.done = False

        cipher = _get_aes_ctr_cipher(key, self.iv)
        if operation == self.encrypt:
            self.operator = cipher.encryptor()
        else:
            self.operator = cipher.decryptor()

    def write(self, data):
        consumed = self.operator.update(data)
        self.buffer.write(consumed)
        return consumed

    def end(self):
        if not self.done:
            self.buffer.write(self.operator.finalize())
            self.deferred.callback(self.buffer)
        self.done = True
        return self.buffer.getvalue()


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
    if len(payload) < PACMAN.size:
        return False
    payload = _split(payload).next()
    if six.indexbytes(payload, 0) != 0x80:
        return False
    unpacked = PACMAN.unpack(payload)
    ts, sch, meth = unpacked[1:4]
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
    return Cipher(algorithms.AES(key), modes.CTR(iv), backend=CRYPTO_BACKEND)


def _split(base64_raw_payload):
    return imap(base64.urlsafe_b64decode, re.split(' ', base64_raw_payload))
