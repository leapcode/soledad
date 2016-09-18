# -*- coding: utf-8 -*-
import json
from twisted.internet.defer import inlineCallbacks

from leap.soledad.client.encdecpool import SyncEncrypterPool

from leap.soledad.common.document import SoledadDocument
from test_soledad.util import BaseSoledadTest

DOC_ID = "mydoc"
DOC_REV = "rev"
DOC_CONTENT = {'simple': 'document'}


class TestSyncEncrypterPool(BaseSoledadTest):

    def setUp(self):
        BaseSoledadTest.setUp(self)
        crypto = self._soledad._crypto
        sync_db = self._soledad._sync_db
        self._pool = SyncEncrypterPool(crypto, sync_db)
        self._pool.start()

    def tearDown(self):
        self._pool.stop()
        BaseSoledadTest.tearDown(self)

    @inlineCallbacks
    def test_get_encrypted_doc_returns_none(self):
        """
        Test that trying to get an encrypted doc from the pool returns None if
        the document was never added for encryption.
        """
        doc = yield self._pool.get_encrypted_doc(DOC_ID, DOC_REV)
        self.assertIsNone(doc)

    @inlineCallbacks
    def test_encrypt_doc_and_get_it_back(self):
        """
        Test that the pool actually encrypts a document added to the queue.
        """
        doc = SoledadDocument(
            doc_id=DOC_ID, rev=DOC_REV, json=json.dumps(DOC_CONTENT))

        yield self._pool.encrypt_doc(doc)
        encrypted = yield self._pool.get_encrypted_doc(DOC_ID, DOC_REV)

        self.assertIsNotNone(encrypted)
