# -*- coding: utf-8 -*-
# test_encdecpool.py
# Copyright (C) 2015 LEAP
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
Tests for encryption and decryption pool.
"""
import json
from random import shuffle

from mock import MagicMock
from twisted.internet.defer import inlineCallbacks

from leap.soledad.client.encdecpool import SyncEncrypterPool
from leap.soledad.client.encdecpool import SyncDecrypterPool

from leap.soledad.common.document import SoledadDocument
from test_soledad.util import BaseSoledadTest
from twisted.internet import defer
from twisted.test.proto_helpers import MemoryReactorClock

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
        self._pool.encrypt_doc(doc)

        # exhaustivelly attempt to get the encrypted document
        encrypted = None
        attempts = 0
        while encrypted is None and attempts < 10:
            encrypted = yield self._pool.get_encrypted_doc(DOC_ID, DOC_REV)
            attempts += 1

        self.assertIsNotNone(encrypted)
        self.assertTrue(attempts < 10)


class TestSyncDecrypterPool(BaseSoledadTest):

    def _insert_doc_cb(self, doc, gen, trans_id):
        """
        Method used to mock the sync's return_doc_cb callback.
        """
        self._inserted_docs.append((doc, gen, trans_id))

    def _setup_pool(self, sync_db=None):
        sync_db = sync_db or self._soledad._sync_db
        return SyncDecrypterPool(
            self._soledad._crypto,
            sync_db,
            source_replica_uid=self._soledad._dbpool.replica_uid,
            insert_doc_cb=self._insert_doc_cb)

    def setUp(self):
        BaseSoledadTest.setUp(self)
        # setup the pool
        self._pool = self._setup_pool()
        # reset the inserted docs mock
        self._inserted_docs = []

    def tearDown(self):
        if self._pool.running:
            self._pool.stop()
        BaseSoledadTest.tearDown(self)

    def test_insert_received_doc(self):
        """
        Test that one document added to the pool is inserted using the
        callback.
        """
        self._pool.start(1)
        self._pool.insert_received_doc(
            DOC_ID, DOC_REV, "{}", 1, "trans_id", 1)

        def _assert_doc_was_inserted(_):
            self.assertEqual(
                self._inserted_docs,
                [(SoledadDocument(DOC_ID, DOC_REV, "{}"), 1, u"trans_id")])

        self._pool.deferred.addCallback(_assert_doc_was_inserted)
        return self._pool.deferred

    def test_looping_control(self):
        """
        Start and stop cleanly.
        """
        self._pool.start(10)
        self.assertTrue(self._pool.running)
        self._pool.stop()
        self.assertFalse(self._pool.running)
        self.assertTrue(self._pool.deferred.called)

    def test_sync_id_col_is_created_if_non_existing_in_docs_recvd_table(self):
        """
        Test that docs_received table is migrated, and has the sync_id column
        """
        mock_run_query = MagicMock(return_value=defer.succeed(None))
        mock_sync_db = MagicMock()
        mock_sync_db.runQuery = mock_run_query
        pool = self._setup_pool(mock_sync_db)
        d = pool.start(10)
        pool.stop()

        def assert_trial_to_create_sync_id_column(_):
            mock_run_query.assert_called_once_with(
                "ALTER TABLE docs_received ADD COLUMN sync_id")

        d.addCallback(assert_trial_to_create_sync_id_column)
        return d

    def test_insert_received_doc_many(self):
        """
        Test that many documents added to the pool are inserted using the
        callback.
        """
        many = 100
        self._pool.start(many)

        # insert many docs in the pool
        for i in xrange(many):
            gen = idx = i + 1
            doc_id = "doc_id: %d" % idx
            rev = "rev: %d" % idx
            content = {'idx': idx}
            trans_id = "trans_id: %d" % idx
            self._pool.insert_received_doc(
                doc_id, rev, content, gen, trans_id, idx)

        def _assert_doc_was_inserted(_):
            self.assertEqual(many, len(self._inserted_docs))
            idx = 1
            for doc, gen, trans_id in self._inserted_docs:
                expected_gen = idx
                expected_doc_id = "doc_id: %d" % idx
                expected_rev = "rev: %d" % idx
                expected_content = json.dumps({'idx': idx})
                expected_trans_id = "trans_id: %d" % idx

                self.assertEqual(expected_doc_id, doc.doc_id)
                self.assertEqual(expected_rev, doc.rev)
                self.assertEqual(expected_content, json.dumps(doc.content))
                self.assertEqual(expected_gen, gen)
                self.assertEqual(expected_trans_id, trans_id)

                idx += 1

        self._pool.deferred.addCallback(_assert_doc_was_inserted)
        return self._pool.deferred

    def test_insert_encrypted_received_doc(self):
        """
        Test that one encrypted document added to the pool is decrypted and
        inserted using the callback.
        """
        crypto = self._soledad._crypto
        doc = SoledadDocument(
            doc_id=DOC_ID, rev=DOC_REV, json=json.dumps(DOC_CONTENT))
        encrypted_content = json.loads(crypto.encrypt_doc(doc))

        # insert the encrypted document in the pool
        self._pool.start(1)
        self._pool.insert_encrypted_received_doc(
            DOC_ID, DOC_REV, encrypted_content, 1, "trans_id", 1)

        def _assert_doc_was_decrypted_and_inserted(_):
            self.assertEqual(1, len(self._inserted_docs))
            self.assertEqual(self._inserted_docs, [(doc, 1, u"trans_id")])

        self._pool.deferred.addCallback(
            _assert_doc_was_decrypted_and_inserted)
        return self._pool.deferred

    @inlineCallbacks
    def test_processing_order(self):
        """
        This test ensures that processing of documents only occur if there is
        a sequence in place.
        """
        reactor_clock = MemoryReactorClock()
        self._pool._loop.clock = reactor_clock

        crypto = self._soledad._crypto

        docs = []
        for i in xrange(1, 10):
            i = str(i)
            doc = SoledadDocument(
                doc_id=DOC_ID + i, rev=DOC_REV + i,
                json=json.dumps(DOC_CONTENT))
            encrypted_content = json.loads(crypto.encrypt_doc(doc))
            docs.append((doc, encrypted_content))

        # insert the encrypted document in the pool
        self._pool.start(10)  # pool is expecting to process 10 docs
        # first three arrives, forming a sequence
        for i, (doc, encrypted_content) in enumerate(docs[:3]):
            gen = idx = i + 1
            yield self._pool.insert_encrypted_received_doc(
                doc.doc_id, doc.rev, encrypted_content, gen, "trans_id", idx)
        # last one arrives alone, so it can't be processed
        doc, encrypted_content = docs[-1]
        yield self._pool.insert_encrypted_received_doc(
            doc.doc_id, doc.rev, encrypted_content, 10, "trans_id", 10)

        reactor_clock.advance(self._pool.DECRYPT_LOOP_PERIOD)
        yield self._pool._decrypt_and_recurse()

        self.assertEqual(3, self._pool._processed_docs)

    def test_insert_encrypted_received_doc_many(self, many=100):
        """
        Test that many encrypted documents added to the pool are decrypted and
        inserted using the callback.
        """
        crypto = self._soledad._crypto
        self._pool.start(many)
        docs = []

        # insert many encrypted docs in the pool
        for i in xrange(many):
            gen = idx = i + 1
            doc_id = "doc_id: %d" % idx
            rev = "rev: %d" % idx
            content = {'idx': idx}
            trans_id = "trans_id: %d" % idx

            doc = SoledadDocument(
                doc_id=doc_id, rev=rev, json=json.dumps(content))

            encrypted_content = json.loads(crypto.encrypt_doc(doc))
            docs.append((doc_id, rev, encrypted_content, gen,
                         trans_id, idx))
        shuffle(docs)

        for doc in docs:
            self._pool.insert_encrypted_received_doc(*doc)

        def _assert_docs_were_decrypted_and_inserted(_):
            self.assertEqual(many, len(self._inserted_docs))
            idx = 1
            for doc, gen, trans_id in self._inserted_docs:
                expected_gen = idx
                expected_doc_id = "doc_id: %d" % idx
                expected_rev = "rev: %d" % idx
                expected_content = json.dumps({'idx': idx})
                expected_trans_id = "trans_id: %d" % idx

                self.assertEqual(expected_doc_id, doc.doc_id)
                self.assertEqual(expected_rev, doc.rev)
                self.assertEqual(expected_content, json.dumps(doc.content))
                self.assertEqual(expected_gen, gen)
                self.assertEqual(expected_trans_id, trans_id)

                idx += 1

        self._pool.deferred.addCallback(
            _assert_docs_were_decrypted_and_inserted)
        return self._pool.deferred

    @inlineCallbacks
    def test_pool_reuse(self):
        """
        The pool is reused between syncs, this test verifies that
        reusing is fine.
        """
        for i in xrange(3):
            yield self.test_insert_encrypted_received_doc_many(5)
            self._inserted_docs = []
            decrypted_docs = yield self._pool._get_docs(encrypted=False)
            # check that decrypted docs staging is clean
            self.assertEquals([], decrypted_docs)
            self._pool.stop()
