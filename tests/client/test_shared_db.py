from leap.soledad.common.document import SoledadDocument
from leap.soledad.client.shared_db import SoledadSharedDatabase

from test_soledad.util import BaseSoledadTest


class SoledadSharedDBTestCase(BaseSoledadTest):

    """
    These tests ensure the functionalities of the shared recovery database.
    """

    def setUp(self):
        BaseSoledadTest.setUp(self)
        self._shared_db = SoledadSharedDatabase(
            'https://provider/', document_factory=SoledadDocument,
            creds=None)

    def tearDown(self):
        BaseSoledadTest.tearDown(self)

    def test__get_remote_doc(self):
        """
        Ensure the shared db is queried with the correct doc_id.
        """
        doc_id = self._soledad.secrets.storage._remote_doc_id()
        self._soledad.secrets.storage._get_remote_doc()
        self._soledad.secrets.storage._shared_db.get_doc.assert_called_with(
            doc_id)

    def test_save_remote(self):
        """
        Ensure recovery document is put into shared recover db.
        """
        doc_id = self._soledad.secrets.storage._remote_doc_id()
        storage = self._soledad.secrets.storage
        storage.save_remote({'content': 'blah'})
        storage._shared_db.get_doc.assert_called_with(doc_id)
        storage._shared_db.put_doc.assert_called_with(self._doc_put)
        self.assertTrue(self._doc_put.doc_id == doc_id)
