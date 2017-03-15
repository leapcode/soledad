# -*- coding: utf-8 -*-
# test_crypto.py
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
Tests for cryptographic related stuff.
"""
import binascii
import base64
import json
import os

from io import BytesIO

import pytest

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

from leap.soledad.common.document import SoledadDocument
from test_soledad.util import BaseSoledadTest
from leap.soledad.client import _crypto

from twisted.trial import unittest
from twisted.internet import defer


snowden1 = (
    "You can't come up against "
    "the world's most powerful intelligence "
    "agencies and not accept the risk. "
    "If they want to get you, over time "
    "they will.")


class AESTest(unittest.TestCase):

    def test_chunked_encryption(self):
        key = 'A' * 32

        fd = BytesIO()
        aes = _crypto.AESWriter(key, _buffer=fd)
        iv = aes.iv

        data = snowden1
        block = 16

        for i in range(len(data) / block):
            chunk = data[i * block:(i + 1) * block]
            aes.write(chunk)
        aes.end()

        ciphertext_chunked = fd.getvalue()
        ciphertext, tag = _aes_encrypt(key, iv, data)

        assert ciphertext_chunked == ciphertext

    def test_decrypt(self):
        key = 'A' * 32
        iv = 'A' * 16

        data = snowden1
        block = 16

        ciphertext, tag = _aes_encrypt(key, iv, data)

        fd = BytesIO()
        aes = _crypto.AESWriter(key, iv, fd, tag=tag)

        for i in range(len(ciphertext) / block):
            chunk = ciphertext[i * block:(i + 1) * block]
            aes.write(chunk)
        aes.end()

        cleartext_chunked = fd.getvalue()
        assert cleartext_chunked == data


class BlobTestCase(unittest.TestCase):

    class doc_info:
        doc_id = 'D-deadbeef'
        rev = '397932e0c77f45fcb7c3732930e7e9b2:1'

    def setUp(self):
        self.inf = BytesIO(snowden1)
        self.blob = _crypto.BlobEncryptor(
            self.doc_info, self.inf,
            armor=True,
            secret='A' * 96)

    @defer.inlineCallbacks
    def test_unarmored_blob_encrypt(self):
        self.blob.armor = False
        encrypted = yield self.blob.encrypt()
        decode = base64.urlsafe_b64decode
        with pytest.raises(TypeError):
            assert map(decode, encrypted.getvalue().split())

    @defer.inlineCallbacks
    def test_default_armored_blob_encrypt(self):
        encrypted = yield self.blob.encrypt()
        decode = base64.urlsafe_b64decode
        assert map(decode, encrypted.getvalue().split())

    @defer.inlineCallbacks
    def test_blob_encryptor(self):
        encrypted = yield self.blob.encrypt()
        preamble, ciphertext = encrypted.getvalue().split()
        preamble = base64.urlsafe_b64decode(preamble)
        ciphertext = base64.urlsafe_b64decode(ciphertext)
        ciphertext = ciphertext[:-16]

        assert len(preamble) == _crypto.PACMAN.size
        unpacked_data = _crypto.PACMAN.unpack(preamble)
        magic, sch, meth, ts, iv, doc_id, rev, _ = unpacked_data
        assert magic == _crypto.BLOB_SIGNATURE_MAGIC
        assert sch == 1
        assert meth == _crypto.ENC_METHOD.aes_256_gcm
        assert iv == self.blob.iv
        assert doc_id == 'D-deadbeef'
        assert rev == self.doc_info.rev

        aes_key = _crypto._get_sym_key_for_doc(
            self.doc_info.doc_id, 'A' * 96)
        assert ciphertext == _aes_encrypt(aes_key, self.blob.iv, snowden1)[0]

        decrypted = _aes_decrypt(aes_key, self.blob.iv, self.blob.tag,
                                 ciphertext, preamble)
        assert str(decrypted) == snowden1

    @defer.inlineCallbacks
    def test_blob_decryptor(self):
        ciphertext = yield self.blob.encrypt()

        decryptor = _crypto.BlobDecryptor(
            self.doc_info, ciphertext,
            secret='A' * 96)
        decrypted = yield decryptor.decrypt()
        assert decrypted.getvalue() == snowden1

    @defer.inlineCallbacks
    def test_unarmored_blob_decryptor(self):
        self.blob.armor = False
        ciphertext = yield self.blob.encrypt()

        decryptor = _crypto.BlobDecryptor(
            self.doc_info, ciphertext,
            armor=False,
            secret='A' * 96)
        decrypted = yield decryptor.decrypt()
        assert decrypted.getvalue() == snowden1

    @defer.inlineCallbacks
    def test_encrypt_and_decrypt(self):
        """
        Check that encrypting and decrypting gives same doc.
        """
        crypto = _crypto.SoledadCrypto('A' * 96)
        payload = {'key': 'someval'}
        doc1 = SoledadDocument('id1', '1', json.dumps(payload))

        encrypted = yield crypto.encrypt_doc(doc1)
        assert encrypted != payload
        assert 'raw' in encrypted
        doc2 = SoledadDocument('id1', '1')
        doc2.set_json(encrypted)
        assert _crypto.is_symmetrically_encrypted(encrypted)
        decrypted = (yield crypto.decrypt_doc(doc2)).getvalue()
        assert len(decrypted) != 0
        assert json.loads(decrypted) == payload

    @defer.inlineCallbacks
    def test_decrypt_with_wrong_tag_raises(self):
        """
        Trying to decrypt a document with wrong MAC should raise.
        """
        crypto = _crypto.SoledadCrypto('A' * 96)
        payload = {'key': 'someval'}
        doc1 = SoledadDocument('id1', '1', json.dumps(payload))

        encrypted = yield crypto.encrypt_doc(doc1)
        encdict = json.loads(encrypted)
        preamble, raw = str(encdict['raw']).split()
        preamble = base64.urlsafe_b64decode(preamble)
        raw = base64.urlsafe_b64decode(raw)
        # mess with tag
        messed = raw[:-16] + '0' * 16

        preamble = base64.urlsafe_b64encode(preamble)
        newraw = preamble + ' ' + base64.urlsafe_b64encode(str(messed))
        doc2 = SoledadDocument('id1', '1')
        doc2.set_json(json.dumps({"raw": str(newraw)}))

        with pytest.raises(_crypto.InvalidBlob):
            yield crypto.decrypt_doc(doc2)


class SoledadSecretsTestCase(BaseSoledadTest):

    def test_generated_secrets_have_correct_length(self):
        expected = self._soledad.secrets.lengths
        for name, length in expected.iteritems():
            secret = getattr(self._soledad.secrets, name)
            self.assertEqual(length, len(secret))


class SoledadCryptoAESTestCase(BaseSoledadTest):

    def test_encrypt_decrypt_sym(self):
        # generate 256-bit key
        key = os.urandom(32)
        iv, cyphertext = _crypto.encrypt_sym('data', key)
        self.assertTrue(cyphertext is not None)
        self.assertTrue(cyphertext != '')
        self.assertTrue(cyphertext != 'data')
        plaintext = _crypto.decrypt_sym(cyphertext, key, iv)
        self.assertEqual('data', plaintext)

    def test_decrypt_with_wrong_iv_raises(self):
        key = os.urandom(32)
        iv, cyphertext = _crypto.encrypt_sym('data', key)
        self.assertTrue(cyphertext is not None)
        self.assertTrue(cyphertext != '')
        self.assertTrue(cyphertext != 'data')
        # get a different iv by changing the first byte
        rawiv = binascii.a2b_base64(iv)
        wrongiv = rawiv
        while wrongiv == rawiv:
            wrongiv = os.urandom(1) + rawiv[1:]
        with pytest.raises(InvalidTag):
            _crypto.decrypt_sym(
                cyphertext, key, iv=binascii.b2a_base64(wrongiv))

    def test_decrypt_with_wrong_key_raises(self):
        key = os.urandom(32)
        iv, cyphertext = _crypto.encrypt_sym('data', key)
        self.assertTrue(cyphertext is not None)
        self.assertTrue(cyphertext != '')
        self.assertTrue(cyphertext != 'data')
        wrongkey = os.urandom(32)  # 256-bits key
        # ensure keys are different in case we are extremely lucky
        while wrongkey == key:
            wrongkey = os.urandom(32)
        with pytest.raises(InvalidTag):
            _crypto.decrypt_sym(cyphertext, wrongkey, iv)


class PreambleTestCase(unittest.TestCase):
    class doc_info:
        doc_id = 'D-deadbeef'
        rev = '397932e0c77f45fcb7c3732930e7e9b2:1'

    def setUp(self):
        self.cleartext = BytesIO(snowden1)
        self.blob = _crypto.BlobEncryptor(
            self.doc_info, self.cleartext,
            secret='A' * 96)

    def test_preamble_starts_with_magic_signature(self):
        preamble = self.blob._encode_preamble()
        assert preamble.startswith(_crypto.BLOB_SIGNATURE_MAGIC)

    def test_preamble_has_cipher_metadata(self):
        preamble = self.blob._encode_preamble()
        unpacked = _crypto.PACMAN.unpack(preamble)
        encryption_scheme, encryption_method = unpacked[1:3]
        assert encryption_scheme in _crypto.ENC_SCHEME
        assert encryption_method in _crypto.ENC_METHOD
        assert unpacked[4] == self.blob.iv

    def test_preamble_has_document_sync_metadata(self):
        preamble = self.blob._encode_preamble()
        unpacked = _crypto.PACMAN.unpack(preamble)
        doc_id, doc_rev = unpacked[5:7]
        assert doc_id == self.doc_info.doc_id
        assert doc_rev == self.doc_info.rev

    def test_preamble_has_document_size(self):
        preamble = self.blob._encode_preamble()
        unpacked = _crypto.PACMAN.unpack(preamble)
        size = unpacked[7]
        assert size == _crypto._ceiling(len(snowden1))

    @defer.inlineCallbacks
    def test_preamble_can_come_without_size(self):
        # XXX: This test case is here only to test backwards compatibility!
        preamble = self.blob._encode_preamble()
        # repack preamble using legacy format, without doc size
        unpacked = _crypto.PACMAN.unpack(preamble)
        preamble_without_size = _crypto.LEGACY_PACMAN.pack(*unpacked[0:7])
        # encrypt it manually for custom tag
        ciphertext, tag = _aes_encrypt(self.blob.sym_key, self.blob.iv,
                                       self.cleartext.getvalue(),
                                       aead=preamble_without_size)
        ciphertext = ciphertext + tag
        # encode it
        ciphertext = base64.urlsafe_b64encode(ciphertext)
        preamble_without_size = base64.urlsafe_b64encode(preamble_without_size)
        # decrypt it
        ciphertext = preamble_without_size + ' ' + ciphertext
        cleartext = yield _crypto.BlobDecryptor(
            self.doc_info, BytesIO(ciphertext),
            secret='A' * 96).decrypt()
        assert cleartext.getvalue() == self.cleartext.getvalue()
        warnings = self.flushWarnings()
        assert len(warnings) == 1
        assert 'legacy document without size' in warnings[0]['message']


def _aes_encrypt(key, iv, data, aead=''):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=backend)
    encryptor = cipher.encryptor()
    if aead:
        encryptor.authenticate_additional_data(aead)
    return encryptor.update(data) + encryptor.finalize(), encryptor.tag


def _aes_decrypt(key, iv, tag, data, aead=''):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=backend)
    decryptor = cipher.decryptor()
    if aead:
        decryptor.authenticate_additional_data(aead)
    return decryptor.update(data) + decryptor.finalize()
