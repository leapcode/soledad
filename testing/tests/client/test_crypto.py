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
import hashlib
import json
import os
import struct

from io import BytesIO

import pytest

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

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
        iv = 'A' * 16

        fd = BytesIO()
        aes = _crypto.AESEncryptor(key, iv, fd)

        data = snowden1
        block = 16

        for i in range(len(data)/block):
            chunk = data[i * block:(i+1)*block]
            aes.write(chunk)
        aes.end()

        ciphertext_chunked = fd.getvalue()
        ciphertext = _aes_encrypt(key, iv, data)

        assert ciphertext_chunked == ciphertext


    def test_decrypt(self):
        key = 'A' * 32
        iv = 'A' * 16

        data = snowden1
        block = 16

        ciphertext = _aes_encrypt(key, iv, data)

        fd = BytesIO()
        aes = _crypto.AESDecryptor(key, iv, fd)

        for i in range(len(ciphertext)/block):
            chunk = ciphertext[i * block:(i+1)*block]
            aes.write(chunk)
        aes.end()

        cleartext_chunked = fd.getvalue()
        assert cleartext_chunked == data



class BlobTestCase(unittest.TestCase):

    class doc_info:
        doc_id = 'D-deadbeef'
        rev = '397932e0c77f45fcb7c3732930e7e9b2:1'

    @defer.inlineCallbacks
    def test_blob_encryptor(self):

        inf = BytesIO()
        inf.write(snowden1)
        inf.seek(0)
        outf = BytesIO()

        blob = _crypto.BlobEncryptor(
            self.doc_info, inf, result=outf,
            secret='A' * 96, iv='B'*16)

        encrypted = yield blob.encrypt()
        data = base64.urlsafe_b64decode(encrypted.getvalue())

        assert data[0] == '\x80'
        ts, sch, meth  = struct.unpack(
            'Qbb', data[1:11])
        assert sch == 1
        assert meth == 1
        iv = data[11:27]
        assert iv == 'B' * 16
        doc_id = data[27:37]
        assert doc_id == 'D-deadbeef'

        rev = data[37:71]
        assert rev == self.doc_info.rev

        ciphertext = data[71:-64]
        aes_key = _crypto._get_sym_key_for_doc(
            self.doc_info.doc_id, 'A'*96)
        assert ciphertext == _aes_encrypt(aes_key, 'B'*16, snowden1)

        decrypted = _aes_decrypt(aes_key, 'B'*16, ciphertext)
        assert str(decrypted) == snowden1


    @defer.inlineCallbacks
    def test_blob_decryptor(self):

        inf = BytesIO()
        inf.write(snowden1)
        inf.seek(0)
        outf = BytesIO()

        blob = _crypto.BlobEncryptor(
            self.doc_info, inf, result=outf,
            secret='A' * 96, iv='B' * 16)
        yield blob.encrypt()

        decryptor = _crypto.BlobDecryptor(
            self.doc_info, outf,
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
        decrypted = yield crypto.decrypt_doc(doc2)
        assert len(decrypted) != 0
        assert json.loads(decrypted) == payload


    @defer.inlineCallbacks
    def test_decrypt_with_wrong_mac_raises(self):
        """
        Trying to decrypt a document with wrong MAC should raise.
        """
        crypto = _crypto.SoledadCrypto('A' * 96)
        payload = {'key': 'someval'}
        doc1 = SoledadDocument('id1', '1', json.dumps(payload))

        encrypted = yield crypto.encrypt_doc(doc1)
        encdict = json.loads(encrypted)
        raw = base64.urlsafe_b64decode(str(encdict['raw']))
        # mess with MAC
        messed = raw[:-64] + '0' * 64
        newraw = base64.urlsafe_b64encode(str(messed))
        doc2 = SoledadDocument('id1', '1')
        doc2.set_json(json.dumps({"raw": str(newraw)}))

        with pytest.raises(_crypto.InvalidBlob):
            decrypted = yield crypto.decrypt_doc(doc2)



class RecoveryDocumentTestCase(BaseSoledadTest):

    def test_export_recovery_document_raw(self):
        rd = self._soledad.secrets._export_recovery_document()
        secret_id = rd[self._soledad.secrets.STORAGE_SECRETS_KEY].items()[0][0]
        # assert exported secret is the same
        secret = self._soledad.secrets._decrypt_storage_secret_version_1(
            rd[self._soledad.secrets.STORAGE_SECRETS_KEY][secret_id])
        self.assertEqual(secret_id, self._soledad.secrets._secret_id)
        self.assertEqual(secret, self._soledad.secrets._secrets[secret_id])
        # assert recovery document structure
        encrypted_secret = rd[
            self._soledad.secrets.STORAGE_SECRETS_KEY][secret_id]
        self.assertTrue(self._soledad.secrets.CIPHER_KEY in encrypted_secret)
        self.assertTrue(
            encrypted_secret[self._soledad.secrets.CIPHER_KEY] == 'aes256')
        self.assertTrue(self._soledad.secrets.LENGTH_KEY in encrypted_secret)
        self.assertTrue(self._soledad.secrets.SECRET_KEY in encrypted_secret)

    def test_import_recovery_document(self):
        rd = self._soledad.secrets._export_recovery_document()
        s = self._soledad_instance()
        s.secrets._import_recovery_document(rd)
        s.secrets.set_secret_id(self._soledad.secrets._secret_id)
        self.assertEqual(self._soledad.storage_secret,
                         s.storage_secret,
                         'Failed settinng secret for symmetric encryption.')
        s.close()


class SoledadSecretsTestCase(BaseSoledadTest):

    def test_new_soledad_instance_generates_one_secret(self):
        self.assertTrue(
            self._soledad.storage_secret is not None,
            "Expected secret to be something different than None")
        number_of_secrets = len(self._soledad.secrets._secrets)
        self.assertTrue(
            number_of_secrets == 1,
            "Expected exactly 1 secret, got %d instead." % number_of_secrets)

    def test_generated_secret_is_of_correct_type(self):
        expected_type = str
        self.assertIsInstance(
            self._soledad.storage_secret, expected_type,
            "Expected secret to be of type %s" % expected_type)

    def test_generated_secret_has_correct_lengt(self):
        expected_length = self._soledad.secrets.GEN_SECRET_LENGTH
        actual_length = len(self._soledad.storage_secret)
        self.assertTrue(
            expected_length == actual_length,
            "Expected secret with length %d, got %d instead."
            % (expected_length, actual_length))

    def test_generated_secret_id_is_sha256_hash_of_secret(self):
        generated = self._soledad.secrets.secret_id
        expected = hashlib.sha256(self._soledad.storage_secret).hexdigest()
        self.assertTrue(
            generated == expected,
            "Expeceted generated secret id to be sha256 hash, got something "
            "else instead.")

    def test_generate_new_secret_generates_different_secret_id(self):
        # generate new secret
        secret_id_1 = self._soledad.secrets.secret_id
        secret_id_2 = self._soledad.secrets._gen_secret()
        self.assertTrue(
            len(self._soledad.secrets._secrets) == 2,
            "Expected exactly 2 secrets.")
        self.assertTrue(
            secret_id_1 != secret_id_2,
            "Expected IDs of secrets to be distinct.")
        self.assertTrue(
            secret_id_1 in self._soledad.secrets._secrets,
            "Expected to find ID of first secret in Soledad Secrets.")
        self.assertTrue(
            secret_id_2 in self._soledad.secrets._secrets,
            "Expected to find ID of second secret in Soledad Secrets.")

    def test__has_secret(self):
        self.assertTrue(
            self._soledad._secrets._has_secret(),
            "Should have a secret at this point")



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

    def test_decrypt_with_wrong_iv_fails(self):
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
        plaintext = _crypto.decrypt_sym(
            cyphertext, key, iv=binascii.b2a_base64(wrongiv))
        self.assertNotEqual('data', plaintext)

    def test_decrypt_with_wrong_key_fails(self):
        key = os.urandom(32)
        iv, cyphertext = _crypto.encrypt_sym('data', key)
        self.assertTrue(cyphertext is not None)
        self.assertTrue(cyphertext != '')
        self.assertTrue(cyphertext != 'data')
        wrongkey = os.urandom(32)  # 256-bits key
        # ensure keys are different in case we are extremely lucky
        while wrongkey == key:
            wrongkey = os.urandom(32)
        plaintext = _crypto.decrypt_sym(cyphertext, wrongkey, iv)
        self.assertNotEqual('data', plaintext)


def _aes_encrypt(key, iv, data):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=backend)
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


def _aes_decrypt(key, iv, data):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=backend)
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()
