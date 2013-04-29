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


from leap.soledad.backends.leap_backend import (
    LeapDocument,
    encrypt_doc_json,
    decrypt_doc_json,
    EncryptionSchemes,
    LeapSyncTarget,
)
from leap.soledad.backends.couch import CouchDatabase
from leap.soledad import KeyAlreadyExists, Soledad
from leap.soledad.crypto import SoledadCrypto
from leap.soledad.tests import BaseSoledadTest
from leap.soledad.tests.test_couch import CouchDBTestCase
from leap.soledad.tests import (
    KEY_FINGERPRINT,
    PRIVATE_KEY,
)
from leap.soledad.tests.u1db_tests import simple_doc, nested_doc, TestCaseWithServer
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
        doc1 = LeapDocument(doc_id='id')
        doc1.content = {'key': 'val'}
        enc_json = encrypt_doc_json(
            self._soledad._crypto, doc1.doc_id, doc1.get_json())
        plain_json = decrypt_doc_json(
            self._soledad._crypto, doc1.doc_id, enc_json)
        doc2 = LeapDocument(doc_id=doc1.doc_id, json=plain_json)
        res1 = doc1.get_json()
        res2 = doc2.get_json()
        self.assertEqual(res1, res2, 'incorrect document encryption')

    def test_encrypt_sym(self):
        """
        Test for successful symmetric encryption.
        """
        doc1 = LeapDocument()
        doc1.content = {'key': 'val'}
        enc_json = json.loads(
            encrypt_doc_json(
                self._soledad._crypto,
                doc1.doc_id, doc1.get_json()))['_encrypted_json']
        self.assertEqual(
            True,
            self._soledad._crypto.is_encrypted_sym(enc_json),
            "could not encrypt with passphrase.")


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
#                          secret_path='/secret.gpg',
#                          local_db_path='/soledad.u1db'):
#        return Soledad(
#            user,
#            '123',
#            gnupg_home=self.tempdir+prefix+gnupg_home,
#            secret_path=self.tempdir+prefix+secret_path,
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
#        if not self._soledad._has_symkey():
#            self._soledad._gen_symkey()
#        self._soledad._load_symkey()
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
#            encrypt_doc_json(
#                self._soledad._crypto, 'doc-id', json.dumps(simple_doc)))
#        db.put_doc(doc)
#        # setup credentials for access to soledad server
#        creds = {
#            'token': {
#                'address': 'leap@leap.se',
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
        rd = self._soledad.export_recovery_document(None)
        self.assertEqual(
            {
                'address': self._soledad._address,
                'symkey': self._soledad._symkey
            },
            json.loads(rd),
            "Could not export raw recovery document."
        )

    def test_export_recovery_document_crypt(self):
        rd = self._soledad.export_recovery_document('123456')
        self.assertEqual(True,
                         self._soledad._crypto.is_encrypted_sym(rd))
        data = {
            'address': self._soledad._address,
            'symkey': self._soledad._symkey,
        }
        raw_data = json.loads(str(self._soledad._crypto.decrypt_sym(
            rd,
            passphrase='123456')))
        self.assertEqual(
            raw_data,
            data,
            "Could not export raw recovery document."
        )

    def test_import_recovery_document_raises_exception(self):
        rd = self._soledad.export_recovery_document(None)
        self.assertRaises(KeyAlreadyExists,
                          self._soledad.import_recovery_document, rd, None)

    def test_import_recovery_document_raw(self):
        rd = self._soledad.export_recovery_document(None)
        s = self._soledad_instance(user='anotheruser@leap.se', prefix='/2')
        s._init_dirs()
        s._crypto = SoledadCrypto(s)
        s.import_recovery_document(rd, None)
        self.assertEqual(self._soledad._address,
                         s._address, 'Failed setting user email.')
        self.assertEqual(self._soledad._symkey,
                         s._symkey,
                         'Failed settinng secret for symmetric encryption.')

    def test_import_recovery_document_crypt(self):
        rd = self._soledad.export_recovery_document('123456')
        s = self._soledad_instance(user='anotheruser@leap.se', prefix='3')
        s._init_dirs()
        s._crypto = SoledadCrypto(s)
        s.import_recovery_document(rd, '123456')
        self.assertEqual(self._soledad._address,
                         s._address, 'Failed setting user email.')
        self.assertEqual(self._soledad._symkey,
                         s._symkey,
                         'Failed settinng secret for symmetric encryption.')


class CryptoMethodsTestCase(BaseSoledadTest):

    def test__gen_symkey(self):
        sol = self._soledad_instance(user='user@leap.se', prefix='/3')
        sol._init_dirs()
        sol._crypto = SoledadCrypto(sol)
        self.assertFalse(sol._has_symkey(), "Should not have a symkey at "
                                            "this point")
        sol._gen_symkey()
        self.assertTrue(sol._has_symkey(), "Could not generate symkey.")

    def test__has_keys(self):
        sol = self._soledad_instance(user='leap@leap.se', prefix='/5')
        sol._init_dirs()
        sol._crypto = SoledadCrypto(sol)
        self.assertFalse(sol._has_keys())
        sol._gen_symkey()
        self.assertTrue(sol._has_keys())
