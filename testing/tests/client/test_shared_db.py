from leap.soledad.common.document import SoledadDocument
from leap.soledad.client.shared_db import SoledadSharedDatabase

from test_soledad.util import BaseSoledadTest
from test_soledad.util import ADDRESS


class SoledadSharedDBTestCase(BaseSoledadTest):

    """
    These tests ensure the functionalities of the shared recovery database.
    """

    def setUp(self):
        BaseSoledadTest.setUp(self)
        self._shared_db = SoledadSharedDatabase(
            'https://provider/', ADDRESS, document_factory=SoledadDocument,
            creds=None)

    def tearDown(self):
        BaseSoledadTest.tearDown(self)

    def test__get_secrets_from_shared_db(self):
        """
        Ensure the shared db is queried with the correct doc_id.
        """
        doc_id = self._soledad.secrets._shared_db_doc_id()
        self._soledad.secrets._get_secrets_from_shared_db()
        self.assertTrue(
            self._soledad.shared_db.get_doc.assert_called_with(
                doc_id) is None,
            'Wrong doc_id when fetching recovery document.')

    def test__put_secrets_in_shared_db(self):
        """
        Ensure recovery document is put into shared recover db.
        """
        doc_id = self._soledad.secrets._shared_db_doc_id()
        self._soledad.secrets._put_secrets_in_shared_db()
        self.assertTrue(
            self._soledad.shared_db.get_doc.assert_called_with(
                doc_id) is None,
            'Wrong doc_id when fetching recovery document.')
        self.assertTrue(
            self._soledad.shared_db.put_doc.assert_called_with(
                self._doc_put) is None,
            'Wrong document when putting recovery document.')
        self.assertTrue(
            self._doc_put.doc_id == doc_id,
            'Wrong doc_id when putting recovery document.')
