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
import shutil
import tempfile
import simplejson as json
import hashlib
import binascii


from leap.common.testing.basetest import BaseLeapTest
from Crypto import Random


from leap.soledad.client import (
    Soledad,
    crypto,
    target,
)
from leap.soledad.common.document import SoledadDocument
from leap.soledad.common.tests import (
    BaseSoledadTest,
    KEY_FINGERPRINT,
    PRIVATE_KEY,
)
from leap.soledad.common.tests.u1db_tests import (
    simple_doc,
    nested_doc,
    TestCaseWithServer,
)


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
        doc1.set_json(target.encrypt_doc(self._soledad._crypto, doc1))
        # assert content is different and includes keys
        self.assertNotEqual(
            simpledoc, doc1.content,
            'incorrect document encryption')
        self.assertTrue(target.ENC_JSON_KEY in doc1.content)
        self.assertTrue(target.ENC_SCHEME_KEY in doc1.content)
        # decrypt doc
        doc1.set_json(target.decrypt_doc(self._soledad._crypto, doc1))
        self.assertEqual(
            simpledoc, doc1.content, 'incorrect document encryption')


class RecoveryDocumentTestCase(BaseSoledadTest):

    def test_export_recovery_document_raw(self):
        rd = self._soledad.export_recovery_document()
        secret_id = rd[self._soledad.STORAGE_SECRETS_KEY].items()[0][0]
        secret = rd[self._soledad.STORAGE_SECRETS_KEY][secret_id]
        self.assertEqual(secret_id, self._soledad._secret_id)
        self.assertEqual(secret, self._soledad._secrets[secret_id])
        self.assertTrue(self._soledad.CIPHER_KEY in secret)
        self.assertTrue(secret[self._soledad.CIPHER_KEY] == 'aes256')
        self.assertTrue(self._soledad.LENGTH_KEY in secret)
        self.assertTrue(self._soledad.SECRET_KEY in secret)

    def test_import_recovery_document(self):
        rd = self._soledad.export_recovery_document()
        s = self._soledad_instance(user='anotheruser@leap.se')
        s.import_recovery_document(rd)
        s._set_secret_id(self._soledad._secret_id)
        self.assertEqual(self._soledad._uuid,
                         s._uuid, 'Failed setting user uuid.')
        self.assertEqual(self._soledad._get_storage_secret(),
                         s._get_storage_secret(),
                         'Failed settinng secret for symmetric encryption.')


class SoledadSecretsTestCase(BaseSoledadTest):

    def test__gen_secret(self):
        # instantiate and save secret_id
        sol = self._soledad_instance(user='user@leap.se')
        self.assertTrue(len(sol._secrets) == 1)
        secret_id_1 = sol.secret_id
        # assert id is hash of secret
        self.assertTrue(
            secret_id_1 == hashlib.sha256(sol.storage_secret).hexdigest())
        # generate new secret
        secret_id_2 = sol._gen_secret()
        self.assertTrue(secret_id_1 != secret_id_2)
        # re-instantiate
        sol = self._soledad_instance(
            user='user@leap.se',
            secret_id=secret_id_1)
        # assert ids are valid
        self.assertTrue(len(sol._secrets) == 2)
        self.assertTrue(secret_id_1 in sol._secrets)
        self.assertTrue(secret_id_2 in sol._secrets)
        # assert format of secret 1
        self.assertTrue(sol.storage_secret is not None)
        self.assertIsInstance(sol.storage_secret, str)
        self.assertTrue(len(sol.storage_secret) == sol.GENERATED_SECRET_LENGTH)
        # assert format of secret 2
        sol._set_secret_id(secret_id_2)
        self.assertTrue(sol.storage_secret is not None)
        self.assertIsInstance(sol.storage_secret, str)
        self.assertTrue(len(sol.storage_secret) == sol.GENERATED_SECRET_LENGTH)
        # assert id is hash of new secret
        self.assertTrue(
            secret_id_2 == hashlib.sha256(sol.storage_secret).hexdigest())

    def test__has_secret(self):
        sol = self._soledad_instance(user='user@leap.se')
        self.assertTrue(sol._has_secret(), "Should have a secret at "
                                           "this point")
        # setting secret id to None should not interfere in the fact we have a
        # secret.
        sol._set_secret_id(None)
        self.assertTrue(sol._has_secret(), "Should have a secret at "
                                           "this point")
        # but not being able to decrypt correctly should
        sol._secrets[sol.secret_id][sol.SECRET_KEY] = None
        self.assertFalse(sol._has_secret())


class MacAuthTestCase(BaseSoledadTest):

    def test_decrypt_with_wrong_mac_raises(self):
        """
        Trying to decrypt a document with wrong MAC should raise.
        """
        simpledoc = {'key': 'val'}
        doc = SoledadDocument(doc_id='id')
        doc.content = simpledoc
        # encrypt doc
        doc.set_json(target.encrypt_doc(self._soledad._crypto, doc))
        self.assertTrue(target.MAC_KEY in doc.content)
        self.assertTrue(target.MAC_METHOD_KEY in doc.content)
        # mess with MAC
        doc.content[target.MAC_KEY] = '1234567890ABCDEF'
        # try to decrypt doc
        self.assertRaises(
            target.WrongMac,
            target.decrypt_doc, self._soledad._crypto, doc)

    def test_decrypt_with_unknown_mac_method_raises(self):
        """
        Trying to decrypt a document with unknown MAC method should raise.
        """
        simpledoc = {'key': 'val'}
        doc = SoledadDocument(doc_id='id')
        doc.content = simpledoc
        # encrypt doc
        doc.set_json(target.encrypt_doc(self._soledad._crypto, doc))
        self.assertTrue(target.MAC_KEY in doc.content)
        self.assertTrue(target.MAC_METHOD_KEY in doc.content)
        # mess with MAC method
        doc.content[target.MAC_METHOD_KEY] = 'mymac'
        # try to decrypt doc
        self.assertRaises(
            target.UnknownMacMethod,
            target.decrypt_doc, self._soledad._crypto, doc)


class SoledadCryptoAESTestCase(BaseSoledadTest):

    def test_encrypt_decrypt_sym(self):
        # generate 256-bit key
        key = Random.new().read(32)
        iv, cyphertext = self._soledad._crypto.encrypt_sym(
            'data', key,
            method=crypto.EncryptionMethods.AES_256_CTR)
        self.assertTrue(cyphertext is not None)
        self.assertTrue(cyphertext != '')
        self.assertTrue(cyphertext != 'data')
        plaintext = self._soledad._crypto.decrypt_sym(
            cyphertext, key, iv=iv,
            method=crypto.EncryptionMethods.AES_256_CTR)
        self.assertEqual('data', plaintext)

    def test_decrypt_with_wrong_iv_fails(self):
        key = Random.new().read(32)
        iv, cyphertext = self._soledad._crypto.encrypt_sym(
            'data', key,
            method=crypto.EncryptionMethods.AES_256_CTR)
        self.assertTrue(cyphertext is not None)
        self.assertTrue(cyphertext != '')
        self.assertTrue(cyphertext != 'data')
        # get a different iv by changing the first byte
        rawiv = binascii.a2b_base64(iv)
        wrongiv = rawiv
        while wrongiv == rawiv:
            wrongiv = os.urandom(1) + rawiv[1:]
        plaintext = self._soledad._crypto.decrypt_sym(
            cyphertext, key, iv=binascii.b2a_base64(wrongiv),
            method=crypto.EncryptionMethods.AES_256_CTR)
        self.assertNotEqual('data', plaintext)

    def test_decrypt_with_wrong_key_fails(self):
        key = Random.new().read(32)
        iv, cyphertext = self._soledad._crypto.encrypt_sym(
            'data', key,
            method=crypto.EncryptionMethods.AES_256_CTR)
        self.assertTrue(cyphertext is not None)
        self.assertTrue(cyphertext != '')
        self.assertTrue(cyphertext != 'data')
        wrongkey = Random.new().read(32)  # 256-bits key
        # ensure keys are different in case we are extremely lucky
        while wrongkey == key:
            wrongkey = Random.new().read(32)
        plaintext = self._soledad._crypto.decrypt_sym(
            cyphertext, wrongkey, iv=iv,
            method=crypto.EncryptionMethods.AES_256_CTR)
        self.assertNotEqual('data', plaintext)


class SoledadCryptoXSalsa20TestCase(BaseSoledadTest):

    def test_encrypt_decrypt_sym(self):
        # generate 256-bit key
        key = Random.new().read(32)
        iv, cyphertext = self._soledad._crypto.encrypt_sym(
            'data', key,
            method=crypto.EncryptionMethods.XSALSA20)
        self.assertTrue(cyphertext is not None)
        self.assertTrue(cyphertext != '')
        self.assertTrue(cyphertext != 'data')
        plaintext = self._soledad._crypto.decrypt_sym(
            cyphertext, key, iv=iv,
            method=crypto.EncryptionMethods.XSALSA20)
        self.assertEqual('data', plaintext)

    def test_decrypt_with_wrong_iv_fails(self):
        key = Random.new().read(32)
        iv, cyphertext = self._soledad._crypto.encrypt_sym(
            'data', key,
            method=crypto.EncryptionMethods.XSALSA20)
        self.assertTrue(cyphertext is not None)
        self.assertTrue(cyphertext != '')
        self.assertTrue(cyphertext != 'data')
        # get a different iv by changing the first byte
        rawiv = binascii.a2b_base64(iv)
        wrongiv = rawiv
        while wrongiv == rawiv:
            wrongiv = os.urandom(1) + rawiv[1:]
        plaintext = self._soledad._crypto.decrypt_sym(
            cyphertext, key, iv=binascii.b2a_base64(wrongiv),
            method=crypto.EncryptionMethods.XSALSA20)
        self.assertNotEqual('data', plaintext)

    def test_decrypt_with_wrong_key_fails(self):
        key = Random.new().read(32)
        iv, cyphertext = self._soledad._crypto.encrypt_sym(
            'data', key,
            method=crypto.EncryptionMethods.XSALSA20)
        self.assertTrue(cyphertext is not None)
        self.assertTrue(cyphertext != '')
        self.assertTrue(cyphertext != 'data')
        wrongkey = Random.new().read(32)  # 256-bits key
        # ensure keys are different in case we are extremely lucky
        while wrongkey == key:
            wrongkey = Random.new().read(32)
        plaintext = self._soledad._crypto.decrypt_sym(
            cyphertext, wrongkey, iv=iv,
            method=crypto.EncryptionMethods.XSALSA20)
        self.assertNotEqual('data', plaintext)
