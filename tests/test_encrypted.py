from leap.soledad.backends.leap_backend import LeapDocument
from leap.soledad.tests import BaseSoledadTest


class EncryptedSyncTestCase(BaseSoledadTest):
    """
    Tests that guarantee that data will always be encrypted when syncing.
    """

    def test_get_set_encrypted(self):
        """
        Test if document encryption is working.
        """
        doc1 = LeapDocument(soledad=self._soledad)
        doc1.content = {'key': 'val'}
        doc2 = LeapDocument(doc_id=doc1.doc_id,
                            encrypted_json=doc1.get_encrypted_json(),
                            soledad=self._soledad)
        res1 = doc1.get_json()
        res2 = doc2.get_json()
        self.assertEqual(res1, res2, 'incorrect document encryption')
