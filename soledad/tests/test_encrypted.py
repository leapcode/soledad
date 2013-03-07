from leap.soledad.backends.leap_backend import LeapDocument
from leap.soledad.tests import BaseSoledadTest
from leap.soledad.tests import KEY_FINGERPRINT

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
