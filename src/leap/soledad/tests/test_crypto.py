import os
from leap.common.testing.basetest import BaseLeapTest
from leap.soledad.backends.leap_backend import LeapDocument
from leap.soledad.tests import BaseSoledadTest
from leap.soledad.tests import (
    KEY_FINGERPRINT,
    PRIVATE_KEY,
)
from leap.soledad import (
    Soledad,
    KeyAlreadyExists,
)
from leap.soledad.util import GPGWrapper

try:
    import simplejson as json
except ImportError:
    import json  # noqa


class EncryptedSyncTestCase(BaseSoledadTest):
    """
    Tests that guarantee that data will always be encrypted when syncing.
    """

    def test_get_set_encrypted_json(self):
        """
        Test getting and setting encrypted content.
        """
        doc1 = LeapDocument(soledad=self._soledad)
        doc1.content = {'key': 'val'}
        doc2 = LeapDocument(doc_id=doc1.doc_id,
                            encrypted_json=doc1.get_encrypted_json(),
                            soledad=self._soledad)
        res1 = doc1.get_json()
        res2 = doc2.get_json()
        self.assertEqual(res1, res2, 'incorrect document encryption')

    def test_successful_symmetric_encryption(self):
        """
        Test for successful symmetric encryption.
        """
        doc1 = LeapDocument(soledad=self._soledad)
        doc1.content = {'key': 'val'}
        enc_json = json.loads(doc1.get_encrypted_json())['_encrypted_json']
        self.assertEqual(
            True,
            self._soledad._gpg.is_encrypted_sym(enc_json),
            "could not encrypt with passphrase.")


class RecoveryDocumentTestCase(BaseSoledadTest):

    def test_export_recovery_document_raw(self):
        rd = self._soledad.export_recovery_document(None)
        self.assertEqual(
            {
                'user': self._soledad._user,
                'privkey': self._soledad._gpg.export_keys(
                    self._soledad._fingerprint,
                    secret=True),
                'symkey': self._soledad._symkey
            },
            json.loads(rd),
            "Could not export raw recovery document."
        )

    def test_export_recovery_document_crypt(self):
        rd = self._soledad.export_recovery_document('123456')
        self.assertEqual(True,
                         self._soledad._gpg.is_encrypted_sym(rd))
        data = {
            'user': self._soledad._user,
            'privkey': self._soledad._gpg.export_keys(
                self._soledad._fingerprint,
                secret=True),
            'symkey': self._soledad._symkey,
        }
        raw_data = json.loads(str(self._soledad._gpg.decrypt(
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
        gnupg_home = self.gnupg_home = "%s/gnupg2" % self.tempdir
        s = Soledad('anotheruser@leap.se', gnupg_home=gnupg_home,
                    bootstrap=False, prefix=self.tempdir)
        s._init_dirs()
        s._gpg = GPGWrapper(gnupghome=gnupg_home)
        s.import_recovery_document(rd, None)
        self.assertEqual(self._soledad._user,
                         s._user, 'Failed setting user email.')
        self.assertEqual(self._soledad._symkey,
                         s._symkey,
                         'Failed settinng secret for symmetric encryption.')
        self.assertEqual(self._soledad._fingerprint,
                         s._fingerprint,
                         'Failed settinng fingerprint.')
        pk1 = self._soledad._gpg.export_keys(
            self._soledad._fingerprint,
            secret=True)
        pk2 = s._gpg.export_keys(s._fingerprint, secret=True)
        self.assertEqual(
            pk1,
            pk2,
            'Failed settinng private key.'
        )

    def test_import_recovery_document_crypt(self):
        rd = self._soledad.export_recovery_document('123456')
        gnupg_home = self.gnupg_home = "%s/gnupg2" % self.tempdir
        s = Soledad('anotheruser@leap.se', gnupg_home=gnupg_home,
                    bootstrap=False, prefix=self.tempdir)
        s._init_dirs()
        s._gpg = GPGWrapper(gnupghome=gnupg_home)
        s.import_recovery_document(rd, '123456')
        self.assertEqual(self._soledad._user,
                         s._user, 'Failed setting user email.')
        self.assertEqual(self._soledad._symkey,
                         s._symkey,
                         'Failed settinng secret for symmetric encryption.')
        self.assertEqual(self._soledad._fingerprint,
                         s._fingerprint,
                         'Failed settinng fingerprint.')
        pk1 = self._soledad._gpg.export_keys(
            self._soledad._fingerprint,
            secret=True)
        pk2 = s._gpg.export_keys(s._fingerprint, secret=True)
        self.assertEqual(
            pk1,
            pk2,
            'Failed settinng private key.'
        )


class SoledadAuxMethods(BaseLeapTest):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def _soledad_instance(self, prefix=None):
        return Soledad('leap@leap.se', bootstrap=False,
                       prefix=prefix or self.tempdir+'/soledad')

    def _gpgwrapper_instance(self):
        return GPGWrapper(gnupghome="%s/gnupg" % self.tempdir)

    def test__init_dirs(self):
        sol = self._soledad_instance()
        sol._init_dirs()
        self.assertTrue(os.path.isdir(sol.prefix))

    def test__init_db(self):
        sol = self._soledad_instance()
        sol._init_dirs()
        sol._gpg = self._gpgwrapper_instance()
        #self._soledad._gpg.import_keys(PUBLIC_KEY)
        if not sol._has_privkey():
            sol._set_privkey(PRIVATE_KEY)
        if not sol._has_symkey():
            sol._gen_symkey()
        sol._load_symkey()
        sol._init_db()
        from leap.soledad.backends.sqlcipher import SQLCipherDatabase
        self.assertIsInstance(sol._db, SQLCipherDatabase)

    def test__gen_privkey(self):
        sol = self._soledad_instance()
        sol._init_dirs()
        sol._gpg = GPGWrapper(gnupghome="%s/gnupg2" % self.tempdir)
        self.assertFalse(sol._has_privkey(), 'Should not have a private key '
                                             'at this point.')
        sol._set_privkey(PRIVATE_KEY)
        self.assertTrue(sol._has_privkey(), 'Could not generate privkey.')

    def test__gen_symkey(self):
        sol = Soledad('leap@leap.se', bootstrap=False,
                      prefix=self.tempdir+'/soledad3')
        sol._init_dirs()
        sol._gpg = GPGWrapper(gnupghome="%s/gnupg3" % self.tempdir)
        if not sol._has_privkey():
            sol._set_privkey(PRIVATE_KEY)
        self.assertFalse(sol._has_symkey(), "Should not have a symkey at "
                                            "this point")
        sol._gen_symkey()
        self.assertTrue(sol._has_symkey(), "Could not generate symkey.")

    def test__has_keys(self):
        sol = self._soledad_instance()
        sol._init_dirs()
        sol._gpg = self._gpgwrapper_instance()
        self.assertFalse(sol._has_keys())
        sol._set_privkey(PRIVATE_KEY)
        self.assertFalse(sol._has_keys())
        sol._gen_symkey()
        self.assertTrue(sol._has_keys())
