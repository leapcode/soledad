from leap.soledad.backends.leap_backend import LeapDocument
from leap.soledad.tests import BaseSoledadTest
from leap.soledad.tests import KEY_FINGERPRINT
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

    def test_export_recovery_document_raw(self):
        rd = self._soledad.export_recovery_document(None)
        self.assertEqual(
            {
                'user_email': self._soledad._user_email,
                'privkey': self._soledad._gpg.export_keys(
                    self._soledad._fingerprint,
                    secret=True),
                'secret': self._soledad._secret
            },
            json.loads(rd),
            "Could not export raw recovery document."
        )

    def test_export_recovery_document_crypt(self):
        rd = self._soledad.export_recovery_document('123456')
        self.assertEqual(True,
                         self._soledad._gpg.is_encrypted_sym(rd))
        data = {
            'user_email': self._soledad._user_email,
            'privkey': self._soledad._gpg.export_keys(
                self._soledad._fingerprint,
                secret=True),
            'secret': self._soledad._secret,
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
                    initialize=False, prefix=self.tempdir)
        s._init_dirs()
        s._gpg = GPGWrapper(gnupghome=gnupg_home)
        s.import_recovery_document(rd, None)
        self.assertEqual(self._soledad._user_email,
                         s._user_email, 'Failed setting user email.')
        self.assertEqual(self._soledad._secret,
                         s._secret,
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
                    initialize=False, prefix=self.tempdir)
        s._init_dirs()
        s._gpg = GPGWrapper(gnupghome=gnupg_home)
        s.import_recovery_document(rd, '123456')
        self.assertEqual(self._soledad._user_email,
                         s._user_email, 'Failed setting user email.')
        self.assertEqual(self._soledad._secret,
                         s._secret,
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
