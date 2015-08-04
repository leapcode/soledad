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
import os
import hashlib
import binascii

from leap.soledad.client import crypto
from leap.soledad.common.document import SoledadDocument
from leap.soledad.common.tests.util import BaseSoledadTest
from leap.soledad.common.crypto import WrongMacError
from leap.soledad.common.crypto import UnknownMacMethodError
from leap.soledad.common.crypto import EncryptionMethods
from leap.soledad.common.crypto import ENC_JSON_KEY
from leap.soledad.common.crypto import ENC_SCHEME_KEY
from leap.soledad.common.crypto import MAC_KEY
from leap.soledad.common.crypto import MAC_METHOD_KEY


class EncryptedSyncTestCase(BaseSoledadTest):

    """
    Tests that guarantee that data will always be encrypted when syncing.
    """

    def test_encrypt_decrypt_json(self):
        """
        Test encrypting and decrypting documents.
        """
        simpledoc = {'key': 'val'}
        doc1 = SoledadDocument(doc_id='id')
        doc1.content = simpledoc

        # encrypt doc
        doc1.set_json(self._soledad._crypto.encrypt_doc(doc1))
        # assert content is different and includes keys
        self.assertNotEqual(
            simpledoc, doc1.content,
            'incorrect document encryption')
        self.assertTrue(ENC_JSON_KEY in doc1.content)
        self.assertTrue(ENC_SCHEME_KEY in doc1.content)
        # decrypt doc
        doc1.set_json(self._soledad._crypto.decrypt_doc(doc1))
        self.assertEqual(
            simpledoc, doc1.content, 'incorrect document encryption')


class RecoveryDocumentTestCase(BaseSoledadTest):

    def test_export_recovery_document_raw(self):
        rd = self._soledad.secrets._export_recovery_document()
        secret_id = rd[self._soledad.secrets.STORAGE_SECRETS_KEY].items()[0][0]
        # assert exported secret is the same
        secret = self._soledad.secrets._decrypt_storage_secret(
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

    def test__gen_secret(self):
        # instantiate and save secret_id
        sol = self._soledad_instance(user='user@leap.se')
        self.assertTrue(len(sol.secrets._secrets) == 1)
        secret_id_1 = sol.secrets.secret_id
        # assert id is hash of secret
        self.assertTrue(
            secret_id_1 == hashlib.sha256(sol.storage_secret).hexdigest())
        # generate new secret
        secret_id_2 = sol.secrets._gen_secret()
        self.assertTrue(secret_id_1 != secret_id_2)
        sol.close()
        # re-instantiate
        sol = self._soledad_instance(user='user@leap.se')
        sol.secrets.set_secret_id(secret_id_1)
        # assert ids are valid
        self.assertTrue(len(sol.secrets._secrets) == 2)
        self.assertTrue(secret_id_1 in sol.secrets._secrets)
        self.assertTrue(secret_id_2 in sol.secrets._secrets)
        # assert format of secret 1
        self.assertTrue(sol.storage_secret is not None)
        self.assertIsInstance(sol.storage_secret, str)
        secret_length = sol.secrets.GEN_SECRET_LENGTH
        self.assertTrue(len(sol.storage_secret) == secret_length)
        # assert format of secret 2
        sol.secrets.set_secret_id(secret_id_2)
        self.assertTrue(sol.storage_secret is not None)
        self.assertIsInstance(sol.storage_secret, str)
        self.assertTrue(len(sol.storage_secret) == secret_length)
        # assert id is hash of new secret
        self.assertTrue(
            secret_id_2 == hashlib.sha256(sol.storage_secret).hexdigest())
        sol.close()

    def test__has_secret(self):
        sol = self._soledad_instance(
            user='user@leap.se', prefix=self.rand_prefix)
        self.assertTrue(
            sol.secrets._has_secret(),
            "Should have a secret at this point")
        # setting secret id to None should not interfere in the fact we have a
        # secret.
        sol.secrets.set_secret_id(None)
        self.assertTrue(
            sol.secrets._has_secret(),
            "Should have a secret at this point")
        # but not being able to decrypt correctly should
        sol.secrets._secrets[sol.secrets.secret_id] = None
        self.assertFalse(sol.secrets._has_secret())
        sol.close()


class MacAuthTestCase(BaseSoledadTest):

    def test_decrypt_with_wrong_mac_raises(self):
        """
        Trying to decrypt a document with wrong MAC should raise.
        """
        simpledoc = {'key': 'val'}
        doc = SoledadDocument(doc_id='id')
        doc.content = simpledoc
        # encrypt doc
        doc.set_json(self._soledad._crypto.encrypt_doc(doc))
        self.assertTrue(MAC_KEY in doc.content)
        self.assertTrue(MAC_METHOD_KEY in doc.content)
        # mess with MAC
        doc.content[MAC_KEY] = '1234567890ABCDEF'
        # try to decrypt doc
        self.assertRaises(
            WrongMacError,
            self._soledad._crypto.decrypt_doc, doc)

    def test_decrypt_with_unknown_mac_method_raises(self):
        """
        Trying to decrypt a document with unknown MAC method should raise.
        """
        simpledoc = {'key': 'val'}
        doc = SoledadDocument(doc_id='id')
        doc.content = simpledoc
        # encrypt doc
        doc.set_json(self._soledad._crypto.encrypt_doc(doc))
        self.assertTrue(MAC_KEY in doc.content)
        self.assertTrue(MAC_METHOD_KEY in doc.content)
        # mess with MAC method
        doc.content[MAC_METHOD_KEY] = 'mymac'
        # try to decrypt doc
        self.assertRaises(
            UnknownMacMethodError,
            self._soledad._crypto.decrypt_doc, doc)


class SoledadCryptoAESTestCase(BaseSoledadTest):

    def test_encrypt_decrypt_sym(self):
        # generate 256-bit key
        key = os.urandom(32)
        iv, cyphertext = crypto.encrypt_sym('data', key)
        self.assertTrue(cyphertext is not None)
        self.assertTrue(cyphertext != '')
        self.assertTrue(cyphertext != 'data')
        plaintext = crypto.decrypt_sym(cyphertext, key, iv)
        self.assertEqual('data', plaintext)

    def test_decrypt_with_wrong_iv_fails(self):
        key = os.urandom(32)
        iv, cyphertext = crypto.encrypt_sym('data', key)
        self.assertTrue(cyphertext is not None)
        self.assertTrue(cyphertext != '')
        self.assertTrue(cyphertext != 'data')
        # get a different iv by changing the first byte
        rawiv = binascii.a2b_base64(iv)
        wrongiv = rawiv
        while wrongiv == rawiv:
            wrongiv = os.urandom(1) + rawiv[1:]
        plaintext = crypto.decrypt_sym(
            cyphertext, key, iv=binascii.b2a_base64(wrongiv))
        self.assertNotEqual('data', plaintext)

    def test_decrypt_with_wrong_key_fails(self):
        key = os.urandom(32)
        iv, cyphertext = crypto.encrypt_sym('data', key)
        self.assertTrue(cyphertext is not None)
        self.assertTrue(cyphertext != '')
        self.assertTrue(cyphertext != 'data')
        wrongkey = os.urandom(32)  # 256-bits key
        # ensure keys are different in case we are extremely lucky
        while wrongkey == key:
            wrongkey = os.urandom(32)
        plaintext = crypto.decrypt_sym(cyphertext, wrongkey, iv)
        self.assertNotEqual('data', plaintext)
