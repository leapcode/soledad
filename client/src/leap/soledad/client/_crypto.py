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
Cryptographic operations for the soledad client.

This module implements streaming crypto operations.
It replaces the old client.crypto module, that will be deprecated in soledad
0.12.

The algorithm for encryptig and decrypting is as follow:

The KEY is a 32 bytes value.
The PREAMBLE is a packed_structure with encryption metadata.
The SEPARATOR is a space.

Encryption
----------

ciphertext = b64_encode(packed_preamble)
             + SEPARATOR
             + b64(AES_GCM(ciphertext) + tag)


Decryption
----------

PREAMBLE + SEPARATOR + PAYLOAD

Ciphertext and Tag CAN be encoded in b64 (armor=True) or raw (False)

check_preamble(b64_decode(ciphertext.split(SEPARATOR)[0])

PAYLOAD = ciphertext + tag

decrypt(PAYLOAD)
"""


import base64
import hashlib
import warnings
import hmac
import os
import struct
import time

from io import BytesIO
from collections import namedtuple

from twisted.internet import defer
from twisted.internet import interfaces
from twisted.web.client import FileBodyProducer

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends.multibackend import MultiBackend
from cryptography.hazmat.backends.openssl.backend \
    import Backend as OpenSSLBackend

from zope.interface import implementer


SECRET_LENGTH = 64
SEPARATOR = ' '

CRYPTO_BACKEND = MultiBackend([OpenSSLBackend()])

PACMAN = struct.Struct('2sbbQ16s255p255pQ')
LEGACY_PACMAN = struct.Struct('2sbbQ16s255p255p')
BLOB_SIGNATURE_MAGIC = '\x13\x37'


ENC_SCHEME = namedtuple('SCHEME', 'symkey')(1)
ENC_METHOD = namedtuple('METHOD', 'aes_256_ctr aes_256_gcm')(1, 2)
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

        content = BytesIO(str(doc.get_json()))
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


def encrypt_sym(data, key, method=ENC_METHOD.aes_256_gcm):
    """
    Encrypt data using AES-256 cipher in selected mode.

    :param data: The data to be encrypted.
    :type data: str
    :param key: The key used to encrypt data (must be 256 bits long).
    :type key: str

    :return: A tuple with the initialization vector and the ciphertext, both
        encoded as base64.
    :rtype: (str, str)
    """
    mode = _mode_by_method(method)
    encryptor = AESWriter(key, mode=mode)
    encryptor.write(data)
    _, ciphertext = encryptor.end()
    iv = base64.b64encode(encryptor.iv)
    tag = encryptor.tag or ''
    return iv, ciphertext + tag


def decrypt_sym(data, key, iv, method=ENC_METHOD.aes_256_gcm):
    """
    Decrypt data using AES-256 cipher in selected mode.

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
    mode = _mode_by_method(method)
    tag = None
    if mode == modes.GCM:
        data, tag = data[:-16], data[-16:]
    decryptor = AESWriter(key, _iv, tag=tag, mode=mode)
    decryptor.write(data)
    _, plaintext = decryptor.end()
    return plaintext


# TODO maybe rename this to Encryptor, since it will be used by blobs an non
# blobs in soledad.
class BlobEncryptor(object):
    """
    Produces encrypted data from the cleartext data associated with a given
    SoledadDocument using AES-256 cipher in GCM mode.

    The production happens using a Twisted's FileBodyProducer, which uses a
    Cooperator to schedule calls and can be paused/resumed. Each call takes at
    most 65536 bytes from the input.

    Both the production input and output are file descriptors, so they can be
    applied to a stream of data.
    """
    # TODO
    # This class needs further work to allow for proper streaming.
    # RIght now we HAVE TO WAIT until the end of the stream before encoding the
    # result. It should be possible to do that just encoding the chunks and
    # passing them to a sink, but for that we have to encode the chunks at
    # proper alignment (3 byes?) with b64 if armor is defined.

    def __init__(self, doc_info, content_fd, secret=None, armor=True,
                 sink=None):
        if not secret:
            raise EncryptionDecryptionError('no secret given')

        self.doc_id = doc_info.doc_id
        self.rev = doc_info.rev
        self.armor = armor

        self._content_fd = content_fd
        self._content_size = self._get_size(content_fd)
        self._producer = FileBodyProducer(content_fd, readSize=2**16)

        self.sym_key = _get_sym_key_for_doc(doc_info.doc_id, secret)
        self._aes = AESWriter(self.sym_key, _buffer=sink)
        self._aes.authenticate(self._encode_preamble())

    def _get_size(self, fd):
        fd.seek(0, os.SEEK_END)
        size = _ceiling(fd.tell())
        fd.seek(0)
        return size

    @property
    def iv(self):
        return self._aes.iv

    @property
    def tag(self):
        return self._aes.tag

    def encrypt(self):
        """
        Starts producing encrypted data from the cleartext data.

        :return: A deferred which will be fired when encryption ends and whose
                 callback will be invoked with the resulting ciphertext.
        :rtype: twisted.internet.defer.Deferred
        """
        # XXX pass a sink to aes?
        d = self._producer.startProducing(self._aes)
        d.addCallback(lambda _: self._end_crypto_stream_and_encode_result())
        return d

    def _encode_preamble(self):
        current_time = int(time.time())

        preamble = PACMAN.pack(
            BLOB_SIGNATURE_MAGIC,
            ENC_SCHEME.symkey,
            ENC_METHOD.aes_256_gcm,
            current_time,
            self.iv,
            str(self.doc_id),
            str(self.rev),
            self._content_size)
        return preamble

    def _end_crypto_stream_and_encode_result(self):

        # TODO ---- this needs to be refactored to allow PROPER streaming
        # We should write the preamble as soon as possible,
        # Is it possible to write the AES stream as soon as it is encrypted by
        # chunks?
        # FIXME also, it needs to be able to encode chunks with base64 if armor

        preamble, encrypted = self._aes.end()
        result = BytesIO()
        result.write(
            base64.urlsafe_b64encode(preamble))
        result.write(SEPARATOR)

        if self.armor:
            result.write(
                base64.urlsafe_b64encode(encrypted + self.tag))
        else:
            result.write(encrypted + self.tag)

        result.seek(0)
        return defer.succeed(result)


# TODO maybe rename this to just Decryptor, since it will be used by blobs
# and non blobs in soledad.
class BlobDecryptor(object):
    """
    Decrypts an encrypted blob associated with a given Document.

    Will raise an exception if the blob doesn't have the expected structure, or
    if the GCM tag doesn't verify.
    """
    # TODO enable the ascii armor = False

    def __init__(self, doc_info, ciphertext_fd, result=None,
                 secret=None, armor=True, start_stream=True, tag=None):
        if not secret:
            raise EncryptionDecryptionError('no secret given')

        self.doc_id = doc_info.doc_id
        self.rev = doc_info.rev
        self.fd = ciphertext_fd
        self.armor = armor
        self._producer = None
        self.result = result or BytesIO()
        self.sym_key = _get_sym_key_for_doc(doc_info.doc_id, secret)
        self.size = None
        self.tag = tag
        preamble, iv = self._consume_preamble()
        assert preamble
        assert iv
        self._aes = AESWriter(self.sym_key, iv, self.result, tag=self.tag)
        self._aes.authenticate(preamble)

        if start_stream:
            self._start_stream()

    def _start_stream(self):
        self._producer = FileBodyProducer(self.fd, readSize=2**16)

    def _consume_preamble(self):
        self.fd.seek(0)
        try:
            preamble, ciphertext = self.fd.getvalue().split(SEPARATOR, 1)
            preamble = base64.urlsafe_b64decode(preamble)
            if self.armor:
                ciphertext = base64.urlsafe_b64decode(ciphertext)
            tag, ciphertext = ciphertext[-16:], ciphertext[:-16]
            self.tag = self.tag or tag

        except (TypeError, ValueError):
            raise InvalidBlob

        try:
            if len(preamble) == LEGACY_PACMAN.size:
                warnings.warn("Decrypting a legacy document without size. " +
                              "This will be deprecated in 0.12. Doc was: " +
                              "doc_id: %s rev: %s" % (self.doc_id, self.rev),
                              Warning)
                unpacked_data = LEGACY_PACMAN.unpack(preamble)
                magic, sch, meth, ts, iv, doc_id, rev = unpacked_data
            elif len(preamble) == PACMAN.size:
                unpacked_data = PACMAN.unpack(preamble)
                magic, sch, meth, ts, iv, doc_id, rev, doc_size = unpacked_data
                self.size = doc_size
            else:
                raise InvalidBlob("Unexpected preamble size %d", len(preamble))
        except struct.error as e:
            raise InvalidBlob(e)

        if magic != BLOB_SIGNATURE_MAGIC:
            raise InvalidBlob
        # TODO check timestamp. Just as a sanity check, but for instance
        # we can refuse to process something that is in the future or
        # too far in the past (1984 would be nice, hehe)
        if sch != ENC_SCHEME.symkey:
            raise InvalidBlob('invalid scheme')
        if meth != ENC_METHOD.aes_256_gcm:
            raise InvalidBlob('invalid encryption scheme')
        if rev != self.rev:
            raise InvalidBlob('invalid revision')
        if doc_id != self.doc_id:
            raise InvalidBlob('invalid doc id')

        self.fd.seek(0)
        self.fd.write(ciphertext)
        self.fd.seek(len(ciphertext))
        self.fd.truncate()
        self.fd.seek(0)
        return preamble, iv

    def _end_stream(self):
        try:
            self._aes.end()
        except InvalidTag:
            raise InvalidBlob('Invalid Tag. Blob authentication failed.')
        fd = self.result
        fd.seek(0)
        return self.result

    def decrypt(self):
        """
        Starts producing encrypted data from the cleartext data.

        :return: A deferred which will be fired when encryption ends and whose
            callback will be invoked with the resulting ciphertext.
        :rtype: twisted.internet.defer.Deferred
        """
        d = self.startProducing()
        d.addCallback(lambda _: self._end_stream())
        return d

    def startProducing(self):
        if not self._producer:
            self._start_stream()
        return self._producer.startProducing(self._aes)

    def endStream(self):
        self._end_stream()

    def write(self, data):
        self._aes.write(data)

    def close(self):
        result = self._aes.end()
        return result


@implementer(interfaces.IConsumer)
class AESWriter(object):
    """
    A Twisted's Consumer implementation that takes an input file descriptor and
    applies AES-256 cipher in GCM mode.

    It is used both for encryption and decryption of a stream, depending of the
    value of the tag parameter. If you pass a tag, it will operate in
    decryption mode, authenticating the preamble. If no tag is passed,
    encryption mode is assumed.
    """

    def __init__(self, key, iv=None, _buffer=None, tag=None, mode=modes.GCM):
        if len(key) != 32:
            raise EncryptionDecryptionError('key is not 256 bits')

        if tag is not None:
            # if tag, we're decrypting
            assert iv is not None

        self.iv = iv or os.urandom(16)
        self.buffer = _buffer or BytesIO()
        cipher = _get_aes_cipher(key, self.iv, tag, mode)
        cipher = cipher.decryptor() if tag else cipher.encryptor()
        self.cipher, self.aead = cipher, ''

    def authenticate(self, data):
        self.aead += data
        self.cipher.authenticate_additional_data(data)

    @property
    def tag(self):
        return getattr(self.cipher, 'tag', None)

    def write(self, data):
        self.buffer.write(self.cipher.update(data))

    def end(self):
        self.buffer.write(self.cipher.finalize())
        return self.aead, self.buffer.getvalue()


def is_symmetrically_encrypted(content):
    """
    Returns True if the document was symmetrically encrypted.
    'EzcB' is the base64 encoding of \x13\x37 magic number and 1 (symmetrically
    encrypted value for enc_scheme flag).

    :param doc: The document content as string
    :type doc: str

    :rtype: bool
    """
    sym_signature = '{"raw": "EzcB'
    return content and content.startswith(sym_signature)


# utils


def _hmac_sha256(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()


def _get_sym_key_for_doc(doc_id, secret):
    key = secret[SECRET_LENGTH:]
    return _hmac_sha256(key, doc_id)


def _get_aes_cipher(key, iv, tag, mode=modes.GCM):
    mode = mode(iv, tag) if mode == modes.GCM else mode(iv)
    return Cipher(algorithms.AES(key), mode, backend=CRYPTO_BACKEND)


def _mode_by_method(method):
    if method == ENC_METHOD.aes_256_gcm:
        return modes.GCM
    else:
        return modes.CTR


def _ceiling(size):
    """
    Some simplistic ceiling scheme that uses powers of 2.
    We report everything below 4096 bytes as that minimum threshold.
    See #8759 for research pending for less simplistic/aggresive strategies.
    """
    for i in xrange(12, 31):
        step = 2 ** i
        if size < step:
            return step
