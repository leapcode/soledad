# -*- coding: utf-8 -*-
# test_soledad.py
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
"""

import os
import mock
import tempfile
import threading


from urlparse import urljoin


from leap.soledad.client import Soledad
from leap.soledad.common.couch import CouchDatabase, CouchServerState
from leap.soledad.common.tests.test_couch import CouchDBTestCase
from leap.soledad.common.tests.u1db_tests import TestCaseWithServer
from leap.soledad.common.tests.test_target import (
    make_token_soledad_app,
    make_leap_document_for_test,
    token_leap_sync_target,
)
from leap.soledad.common.tests.test_server import _couch_ensure_database


REPEAT_TIMES = 20


# monkey path CouchServerState so it can ensure databases.

CouchServerState.ensure_database = _couch_ensure_database


class CouchAtomicityTestCase(CouchDBTestCase, TestCaseWithServer):

    @staticmethod
    def make_app_after_state(state):
        return make_token_soledad_app(state)

    make_document_for_test = make_leap_document_for_test

    sync_target = token_leap_sync_target

    def _soledad_instance(self, user='user-uuid', passphrase=u'123',
                          prefix='',
                          secrets_path=Soledad.STORAGE_SECRETS_FILE_NAME,
                          local_db_path='soledad.u1db', server_url='',
                          cert_file=None, auth_token=None, secret_id=None):
        """
        Instantiate Soledad.
        """

        # this callback ensures we save a document which is sent to the shared
        # db.
        def _put_doc_side_effect(doc):
            self._doc_put = doc

        # we need a mocked shared db or else Soledad will try to access the
        # network to find if there are uploaded secrets.
        class MockSharedDB(object):

            get_doc = mock.Mock(return_value=None)
            put_doc = mock.Mock(side_effect=_put_doc_side_effect)
            lock = mock.Mock(return_value=('atoken', 300))
            unlock = mock.Mock()

            def __call__(self):
                return self

        Soledad._shared_db = MockSharedDB()
        return Soledad(
            user,
            passphrase,
            secrets_path=os.path.join(self.tempdir, prefix, secrets_path),
            local_db_path=os.path.join(
                self.tempdir, prefix, local_db_path),
            server_url=server_url,
            cert_file=cert_file,
            auth_token=auth_token,
            secret_id=secret_id)

    def make_app(self):
        self.request_state = CouchServerState(self._couch_url, 'shared',
                                              'tokens')
        return self.make_app_after_state(self.request_state)

    def setUp(self):
        TestCaseWithServer.setUp(self)
        CouchDBTestCase.setUp(self)
        self._couch_url = 'http://localhost:' + str(self.wrapper.port)
        self.db = CouchDatabase.open_database(
            urljoin(self._couch_url, 'user-user-uuid'),
            create=True,
            replica_uid='replica',
            ensure_ddocs=True)
        self.tempdir = tempfile.mkdtemp(prefix="leap_tests-")

    def tearDown(self):
        self.db.delete_database()
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
        ops = 1
        docs = [doc.doc_id]
        for i in range(0, REPEAT_TIMES):
            self.assertEqual(
                i+1, len(self.db._get_transaction_log()))
            doc.content['ops'] += 1
            self.db.put_doc(doc)
            docs.append(doc.doc_id)

        # assert length of transaction_log
        transaction_log = self.db._get_transaction_log()
        self.assertEqual(
            REPEAT_TIMES+1, len(transaction_log))

        # assert that all entries in the log belong to the same doc
        self.assertEqual(REPEAT_TIMES+1, len(docs))
        for doc_id in docs:
            self.assertEqual(
                REPEAT_TIMES+1,
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
                2*i+1, len(self.db._get_transaction_log()))
            docs.append(doc.doc_id)
            self.db.delete_doc(doc)
            self.assertEqual(
                2*i+2, len(self.db._get_transaction_log()))

        # assert length of transaction_log
        transaction_log = self.db._get_transaction_log()
        self.assertEqual(
            2*REPEAT_TIMES, len(transaction_log))

        # assert that each doc appears twice in the transaction_log
        self.assertEqual(REPEAT_TIMES, len(docs))
        for doc_id in docs:
            self.assertEqual(
                2,
                len(filter(lambda t: t[0] == doc_id, transaction_log)))

    def test_correct_sync_log_after_sequential_syncs(self):
        """
        Assert that the sync_log increases accordingly with sequential syncs.
        """
        self.startServer()
        sol = self._soledad_instance(
            auth_token='auth-token',
            server_url=self.getURL())

        def _create_docs_and_sync(sol, syncs):
            # create a lot of documents
            for i in range(0, REPEAT_TIMES):
                sol.create_doc({})
            # assert sizes of transaction and sync logs
            self.assertEqual(
                syncs*REPEAT_TIMES,
                len(self.db._get_transaction_log()))
            self.assertEqual(
                1 if syncs > 0 else 0,
                len(self.db._database.view('syncs/log').rows))
            # sync to the remote db
            sol.sync()
            gen, docs = self.db.get_all_docs()
            self.assertEqual((syncs+1)*REPEAT_TIMES, gen)
            self.assertEqual((syncs+1)*REPEAT_TIMES, len(docs))
            # assert sizes of transaction and sync logs
            self.assertEqual((syncs+1)*REPEAT_TIMES,
                             len(self.db._get_transaction_log()))
            sync_log_rows = self.db._database.view('syncs/log').rows
            sync_log = sync_log_rows[0].value
            replica_uid = sync_log_rows[0].key
            known_gen = sync_log['known_generation']
            known_trans_id = sync_log['known_transaction_id']
            # assert sync_log has exactly 1 row
            self.assertEqual(1, len(sync_log_rows))
            # assert it has the correct replica_uid, gen and trans_id
            self.assertEqual(sol._db._replica_uid, replica_uid)
            sol_gen, sol_trans_id = sol._db._get_generation_info()
            self.assertEqual(sol_gen, known_gen)
            self.assertEqual(sol_trans_id, known_trans_id)

        _create_docs_and_sync(sol, 0)
        _create_docs_and_sync(sol, 1)

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
            2*REPEAT_TIMES, len(transaction_log))
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
        threads = []
        docs = []
        pool = threading.BoundedSemaphore(value=1)
        self.startServer()
        sol = self._soledad_instance(
            auth_token='auth-token',
            server_url=self.getURL())

        def _run_method(self):
            # create a lot of documents
            doc = self._params['sol'].create_doc({})
            pool.acquire()
            docs.append(doc.doc_id)
            pool.release()

        # launch threads to create documents in parallel
        for i in range(0, REPEAT_TIMES):
            thread = self._WorkerThread(
                {'sol': sol, 'syncs': i},
                _run_method)
            thread.start()
            threads.append(thread)

        # wait for threads to finish
        for thread in threads:
            thread.join()
        
        # do the sync!
        sol.sync()

        transaction_log = self.db._get_transaction_log()
        self.assertEqual(REPEAT_TIMES, len(transaction_log))
        # assert all documents are in the remote log
        self.assertEqual(REPEAT_TIMES, len(docs))
        for doc_id in docs:
            self.assertEqual(
                1,
                len(filter(lambda t: t[0] == doc_id, transaction_log)))

    def test_concurrent_syncs_do_not_fail(self):
        """
        Assert that concurrent attempts to sync end up being executed
        sequentially and do not fail.
        """
        threads = []
        docs = []
        pool = threading.BoundedSemaphore(value=1)
        self.startServer()
        sol = self._soledad_instance(
            auth_token='auth-token',
            server_url=self.getURL())

        def _run_method(self):
            # create a lot of documents
            doc = self._params['sol'].create_doc({})
            # do the sync!
            sol.sync()
            pool.acquire()
            docs.append(doc.doc_id)
            pool.release()

        # launch threads to create documents in parallel
        for i in range(0, REPEAT_TIMES):
            thread = self._WorkerThread(
                {'sol': sol, 'syncs': i},
                _run_method)
            thread.start()
            threads.append(thread)

        # wait for threads to finish
        for thread in threads:
            thread.join()

        transaction_log = self.db._get_transaction_log()
        self.assertEqual(REPEAT_TIMES, len(transaction_log))
        # assert all documents are in the remote log
        self.assertEqual(REPEAT_TIMES, len(docs))
        for doc_id in docs:
            self.assertEqual(
                1,
                len(filter(lambda t: t[0] == doc_id, transaction_log)))
