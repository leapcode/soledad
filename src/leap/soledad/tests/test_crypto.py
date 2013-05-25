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
try:
    import simplejson as json
except ImportError:
    import json  # noqa
import hashlib


from leap.soledad.backends.leap_backend import (
    LeapDocument,
    encrypt_doc,
    decrypt_doc,
    EncryptionSchemes,
    LeapSyncTarget,
    ENC_JSON_KEY,
    ENC_SCHEME_KEY,
    MAC_METHOD_KEY,
    MAC_KEY,
    UnknownMacMethod,
    WrongMac,
)
from leap.soledad.backends.couch import CouchDatabase
from leap.soledad import Soledad
from leap.soledad.crypto import SoledadCrypto
from leap.soledad.tests import BaseSoledadTest
from leap.soledad.tests.test_couch import CouchDBTestCase
from leap.soledad.tests import (
    KEY_FINGERPRINT,
    PRIVATE_KEY,
)
from leap.soledad.tests.u1db_tests import (
    simple_doc,
    nested_doc,
    TestCaseWithServer,
)
from leap.soledad.tests.test_leap_backend import make_leap_document_for_test
from leap.soledad.backends.couch import CouchServerState


class EncryptedSyncTestCase(BaseSoledadTest):
    """
    Tests that guarantee that data will always be encrypted when syncing.
    """

    def test_encrypt_decrypt_json(self):
        """
        Test encrypting and decrypting documents.
        """
        simpledoc = {'key': 'val'}
        doc1 = LeapDocument(doc_id='id')
        doc1.content = simpledoc
        # encrypt doc
        doc1.set_json(encrypt_doc(self._soledad._crypto, doc1))
        # assert content is different and includes keys
        self.assertNotEqual(
            simpledoc, doc1.content,
            'incorrect document encryption')
        self.assertTrue(ENC_JSON_KEY in doc1.content)
        self.assertTrue(ENC_SCHEME_KEY in doc1.content)
        # decrypt doc
        doc1.set_json(decrypt_doc(self._soledad._crypto, doc1))
        self.assertEqual(
            simpledoc, doc1.content, 'incorrect document encryption')


#from leap.soledad.server import SoledadApp, SoledadAuthMiddleware
#
#
#def make_token_leap_app(test, state):
#    app = SoledadApp(state)
#    application = SoledadAuthMiddleware(app, prefix='/soledad/')
#    return application
#
#
#def leap_sync_target(test, path):
#    return LeapSyncTarget(test.getURL(path))
#
#
#def token_leap_sync_target(test, path):
#    st = leap_sync_target(test, 'soledad/' + path)
#    st.set_token_credentials('any_user', 'any_token')
#    return st
#
#
#class EncryptedCouchSyncTest(CouchDBTestCase, TestCaseWithServer):
#
#    make_app_with_state = make_token_leap_app
#
#    make_document_for_test = make_leap_document_for_test
#
#    sync_target = token_leap_sync_target
#
#    def make_app(self):
#        # potential hook point
#        self.request_state = CouchServerState(self._couch_url)
#        return self.make_app_with_state(self.request_state)
#
#    def _soledad_instance(self, user='leap@leap.se', prefix='',
#                          bootstrap=False, gnupg_home='/gnupg',
#                          secrets_path='/secret.gpg',
#                          local_db_path='/soledad.u1db'):
#        return Soledad(
#            user,
#            '123',
#            gnupg_home=self.tempdir+prefix+gnupg_home,
#            secrets_path=self.tempdir+prefix+secrets_path,
#            local_db_path=self.tempdir+prefix+local_db_path,
#            bootstrap=bootstrap)
#
#    def setUp(self):
#        CouchDBTestCase.setUp(self)
#        TestCaseWithServer.setUp(self)
#        self.tempdir = tempfile.mkdtemp(suffix='.couch.test')
#        # initialize soledad by hand so we can control keys
#        self._soledad = self._soledad_instance('leap@leap.se')
#        self._soledad._init_dirs()
#        self._soledad._crypto = SoledadCrypto(self._soledad)
#        if not self._soledad._has_get_storage_secret()():
#            self._soledad._gen_get_storage_secret()()
#        self._soledad._load_get_storage_secret()()
#        self._soledad._init_db()
#
#    def tearDown(self):
#        shutil.rmtree(self.tempdir)
#
#    def test_encrypted_sym_sync(self):
#        # get direct access to couchdb
#        import ipdb; ipdb.set_trace()
#        self._couch_url = 'http://localhost:' + str(self.wrapper.port)
#        db = CouchDatabase(self._couch_url, 'testdb')
#        # create and encrypt a doc to insert directly in couchdb
#        doc = LeapDocument('doc-id')
#        doc.set_json(
#            encrypt_doc(
#                self._soledad._crypto, 'doc-id', json.dumps(simple_doc)))
#        db.put_doc(doc)
#        # setup credentials for access to soledad server
#        creds = {
#            'token': {
#                'uuid': 'leap@leap.se',
#                'token': '1234',
#            }
#        }
#        # sync local soledad db with server
#        self.assertTrue(self._soledad.get_doc('doc-id') is None)
#        self.startServer()
#        # TODO fix sync for test.
#        #self._soledad.sync(self.getURL('soledad/testdb'), creds)
#        # get and check doc
#        doc = self._soledad.get_doc('doc-id')
#        # TODO: fix below.
#        #self.assertTrue(doc is not None)
#        #self.assertTrue(doc.content == simple_doc)


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


class CryptoMethodsTestCase(BaseSoledadTest):

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
        doc = LeapDocument(doc_id='id')
        doc.content = simpledoc
        # encrypt doc
        doc.set_json(encrypt_doc(self._soledad._crypto, doc))
        self.assertTrue(MAC_KEY in doc.content)
        self.assertTrue(MAC_METHOD_KEY in doc.content)
        # mess with MAC
        doc.content[MAC_KEY] = '1234567890ABCDEF'
        # try to decrypt doc
        self.assertRaises(
            WrongMac,
            decrypt_doc, self._soledad._crypto, doc)

    def test_decrypt_with_unknown_mac_method_raises(self):
        """
        Trying to decrypt a document with unknown MAC method should raise.
        """
        simpledoc = {'key': 'val'}
        doc = LeapDocument(doc_id='id')
        doc.content = simpledoc
        # encrypt doc
        doc.set_json(encrypt_doc(self._soledad._crypto, doc))
        self.assertTrue(MAC_KEY in doc.content)
        self.assertTrue(MAC_METHOD_KEY in doc.content)
        # mess with MAC method
        doc.content[MAC_METHOD_KEY] = 'mymac'
        # try to decrypt doc
        self.assertRaises(
            UnknownMacMethod,
            decrypt_doc, self._soledad._crypto, doc)
