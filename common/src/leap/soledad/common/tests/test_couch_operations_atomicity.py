# -*- coding: utf-8 -*-
# test_couch_operations_atomicity.py
# Copyright (C) 2013, 2014 LEAP
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
Test atomicity of couch operations.
"""
import os
import tempfile
import threading

from urlparse import urljoin
from twisted.internet import defer
from uuid import uuid4

from leap.soledad.client import Soledad
from leap.soledad.common.couch.state import CouchServerState
from leap.soledad.common.couch import CouchDatabase

from leap.soledad.common.tests.util import (
    make_token_soledad_app,
    make_soledad_document_for_test,
    soledad_sync_target,
)
from leap.soledad.common.tests.test_couch import CouchDBTestCase
from leap.soledad.common.tests.u1db_tests import TestCaseWithServer


REPEAT_TIMES = 20


class CouchAtomicityTestCase(CouchDBTestCase, TestCaseWithServer):

    @staticmethod
    def make_app_after_state(state):
        return make_token_soledad_app(state)

    make_document_for_test = make_soledad_document_for_test

    sync_target = soledad_sync_target

    def _soledad_instance(self, user=None, passphrase=u'123',
                          prefix='',
                          secrets_path='secrets.json',
                          local_db_path='soledad.u1db', server_url='',
                          cert_file=None, auth_token=None):
        """
        Instantiate Soledad.
        """
        user = user or self.user

        # this callback ensures we save a document which is sent to the shared
        # db.
        def _put_doc_side_effect(doc):
            self._doc_put = doc

        soledad = Soledad(
            user,
            passphrase,
            secrets_path=os.path.join(self.tempdir, prefix, secrets_path),
            local_db_path=os.path.join(
                self.tempdir, prefix, local_db_path),
            server_url=server_url,
            cert_file=cert_file,
            auth_token=auth_token,
            shared_db=self.get_default_shared_mock(_put_doc_side_effect))
        self.addCleanup(soledad.close)
        return soledad

    def make_app(self):
        self.request_state = CouchServerState(self.couch_url)
        return self.make_app_after_state(self.request_state)

    def setUp(self):
        TestCaseWithServer.setUp(self)
        CouchDBTestCase.setUp(self)
        self.user = ('user-%s' % uuid4().hex)
        self.db = CouchDatabase.open_database(
            urljoin(self.couch_url, 'user-' + self.user),
            create=True,
            replica_uid='replica',
            ensure_ddocs=True)
        self.tempdir = tempfile.mkdtemp(prefix="leap_tests-")
        self.startTwistedServer()

    def tearDown(self):
        self.db.delete_database()
        self.db.close()
        CouchDBTestCase.tearDown(self)
        TestCaseWithServer.tearDown(self)

    #
    # Sequential tests
    #

    def test_correct_transaction_log_after_sequential_puts(self):
        """
        Assert that the transaction_log increases accordingly with sequential
        puts.
        """
        doc = self.db.create_doc({'ops': 0})
        docs = [doc.doc_id]
        for i in range(0, REPEAT_TIMES):
            self.assertEqual(
                i + 1, len(self.db._get_transaction_log()))
            doc.content['ops'] += 1
            self.db.put_doc(doc)
            docs.append(doc.doc_id)

        # assert length of transaction_log
        transaction_log = self.db._get_transaction_log()
        self.assertEqual(
            REPEAT_TIMES + 1, len(transaction_log))

        # assert that all entries in the log belong to the same doc
        self.assertEqual(REPEAT_TIMES + 1, len(docs))
        for doc_id in docs:
            self.assertEqual(
                REPEAT_TIMES + 1,
                len(filter(lambda t: t[0] == doc_id, transaction_log)))

    def test_correct_transaction_log_after_sequential_deletes(self):
        """
        Assert that the transaction_log increases accordingly with sequential
        puts and deletes.
        """
        docs = []
        for i in range(0, REPEAT_TIMES):
            doc = self.db.create_doc({'ops': 0})
            self.assertEqual(
                2 * i + 1, len(self.db._get_transaction_log()))
            docs.append(doc.doc_id)
            self.db.delete_doc(doc)
            self.assertEqual(
                2 * i + 2, len(self.db._get_transaction_log()))

        # assert length of transaction_log
        transaction_log = self.db._get_transaction_log()
        self.assertEqual(
            2 * REPEAT_TIMES, len(transaction_log))

        # assert that each doc appears twice in the transaction_log
        self.assertEqual(REPEAT_TIMES, len(docs))
        for doc_id in docs:
            self.assertEqual(
                2,
                len(filter(lambda t: t[0] == doc_id, transaction_log)))

    @defer.inlineCallbacks
    def test_correct_sync_log_after_sequential_syncs(self):
        """
        Assert that the sync_log increases accordingly with sequential syncs.
        """
        sol = self._soledad_instance(
            auth_token='auth-token',
            server_url=self.getURL())
        source_replica_uid = sol._dbpool.replica_uid

        def _create_docs():
            deferreds = []
            for i in xrange(0, REPEAT_TIMES):
                deferreds.append(sol.create_doc({}))
            return defer.gatherResults(deferreds)

        def _assert_transaction_and_sync_logs(results, sync_idx):
            # assert sizes of transaction and sync logs
            self.assertEqual(
                sync_idx * REPEAT_TIMES,
                len(self.db._get_transaction_log()))
            gen, _ = self.db._get_replica_gen_and_trans_id(source_replica_uid)
            self.assertEqual(sync_idx * REPEAT_TIMES, gen)

        def _assert_sync(results, sync_idx):
            gen, docs = results
            self.assertEqual((sync_idx + 1) * REPEAT_TIMES, gen)
            self.assertEqual((sync_idx + 1) * REPEAT_TIMES, len(docs))
            # assert sizes of transaction and sync logs
            self.assertEqual((sync_idx + 1) * REPEAT_TIMES,
                             len(self.db._get_transaction_log()))
            target_known_gen, target_known_trans_id = \
                self.db._get_replica_gen_and_trans_id(source_replica_uid)
            # assert it has the correct gen and trans_id
            conn_key = sol._dbpool._u1dbconnections.keys().pop()
            conn = sol._dbpool._u1dbconnections[conn_key]
            sol_gen, sol_trans_id = conn._get_generation_info()
            self.assertEqual(sol_gen, target_known_gen)
            self.assertEqual(sol_trans_id, target_known_trans_id)

        # sync first time and assert success
        results = yield _create_docs()
        _assert_transaction_and_sync_logs(results, 0)
        yield sol.sync()
        results = yield sol.get_all_docs()
        _assert_sync(results, 0)

        # create more docs, sync second time and assert success
        results = yield _create_docs()
        _assert_transaction_and_sync_logs(results, 1)
        yield sol.sync()
        results = yield sol.get_all_docs()
        _assert_sync(results, 1)

    #
    # Concurrency tests
    #

    class _WorkerThread(threading.Thread):

        def __init__(self, params, run_method):
            threading.Thread.__init__(self)
            self._params = params
            self._run_method = run_method

        def run(self):
            self._run_method(self)

    def test_correct_transaction_log_after_concurrent_puts(self):
        """
        Assert that the transaction_log increases accordingly with concurrent
        puts.
        """
        pool = threading.BoundedSemaphore(value=1)
        threads = []
        docs = []

        def _run_method(self):
            doc = self._params['db'].create_doc({})
            pool.acquire()
            self._params['docs'].append(doc.doc_id)
            pool.release()

        for i in range(0, REPEAT_TIMES):
            thread = self._WorkerThread(
                {'docs': docs, 'db': self.db},
                _run_method)
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()

        # assert length of transaction_log
        transaction_log = self.db._get_transaction_log()
        self.assertEqual(
            REPEAT_TIMES, len(transaction_log))

        # assert all documents are in the log
        self.assertEqual(REPEAT_TIMES, len(docs))
        for doc_id in docs:
            self.assertEqual(
                1,
                len(filter(lambda t: t[0] == doc_id, transaction_log)))

    def test_correct_transaction_log_after_concurrent_deletes(self):
        """
        Assert that the transaction_log increases accordingly with concurrent
        puts and deletes.
        """
        threads = []
        docs = []
        pool = threading.BoundedSemaphore(value=1)

        # create/delete method that will be run concurrently
        def _run_method(self):
            doc = self._params['db'].create_doc({})
            pool.acquire()
            docs.append(doc.doc_id)
            pool.release()
            self._params['db'].delete_doc(doc)

        # launch concurrent threads
        for i in range(0, REPEAT_TIMES):
            thread = self._WorkerThread({'db': self.db}, _run_method)
            thread.start()
            threads.append(thread)

        # wait for threads to finish
        for thread in threads:
            thread.join()

        # assert transaction log
        transaction_log = self.db._get_transaction_log()
        self.assertEqual(
            2 * REPEAT_TIMES, len(transaction_log))
        # assert that each doc appears twice in the transaction_log
        self.assertEqual(REPEAT_TIMES, len(docs))
        for doc_id in docs:
            self.assertEqual(
                2,
                len(filter(lambda t: t[0] == doc_id, transaction_log)))

    def test_correct_sync_log_after_concurrent_puts_and_sync(self):
        """
        Assert that the sync_log is correct after concurrent syncs.
        """
        docs = []

        sol = self._soledad_instance(
            auth_token='auth-token',
            server_url=self.getURL())

        def _save_doc_ids(results):
            for doc in results:
                docs.append(doc.doc_id)

        # create documents in parallel
        deferreds = []
        for i in range(0, REPEAT_TIMES):
            d = sol.create_doc({})
            deferreds.append(d)

        # wait for documents creation and sync
        d = defer.gatherResults(deferreds)
        d.addCallback(_save_doc_ids)
        d.addCallback(lambda _: sol.sync())

        def _assert_logs(results):
            transaction_log = self.db._get_transaction_log()
            self.assertEqual(REPEAT_TIMES, len(transaction_log))
            # assert all documents are in the remote log
            self.assertEqual(REPEAT_TIMES, len(docs))
            for doc_id in docs:
                self.assertEqual(
                    1,
                    len(filter(lambda t: t[0] == doc_id, transaction_log)))

        d.addCallback(_assert_logs)
        d.addCallback(lambda _: sol.close())

        return d

    @defer.inlineCallbacks
    def test_concurrent_syncs_do_not_fail(self):
        """
        Assert that concurrent attempts to sync end up being executed
        sequentially and do not fail.
        """
        docs = []

        sol = self._soledad_instance(
            auth_token='auth-token',
            server_url=self.getURL())

        deferreds = []
        for i in xrange(0, REPEAT_TIMES):
            d = sol.create_doc({})
            d.addCallback(lambda doc: docs.append(doc.doc_id))
            d.addCallback(lambda _: sol.sync())
            deferreds.append(d)
        yield defer.gatherResults(deferreds, consumeErrors=True)

        transaction_log = self.db._get_transaction_log()
        self.assertEqual(REPEAT_TIMES, len(transaction_log))
        # assert all documents are in the remote log
        self.assertEqual(REPEAT_TIMES, len(docs))
        for doc_id in docs:
            self.assertEqual(
                1,
                len(filter(lambda t: t[0] == doc_id, transaction_log)))
