# -*- coding: utf-8 -*-
# test_sync.py
# Copyright (C) 2014 LEAP
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


import mock
import os
import json
import tempfile
import threading
import time
from urlparse import urljoin

from leap.soledad.common.couch import (
    CouchServerState,
    CouchDatabase,
)

from leap.soledad.common.tests.u1db_tests import (
    TestCaseWithServer,
    simple_doc,
)
from leap.soledad.common.tests.test_couch import CouchDBTestCase
from leap.soledad.common.tests.test_target import (
    make_token_soledad_app,
    make_leap_document_for_test,
    token_leap_sync_target,
)

from leap.soledad.client import (
    Soledad,
    target,
)


class InterruptableSyncTestCase(
        CouchDBTestCase, TestCaseWithServer):
    """
    Tests for encrypted sync using Soledad server backed by a couch database.
    """

    @staticmethod
    def make_app_with_state(state):
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
        return self.make_app_with_state(self.request_state)

    def setUp(self):
        TestCaseWithServer.setUp(self)
        CouchDBTestCase.setUp(self)
        self.tempdir = tempfile.mkdtemp(prefix="leap_tests-")
        self._couch_url = 'http://localhost:' + str(self.wrapper.port)

    def tearDown(self):
        CouchDBTestCase.tearDown(self)
        TestCaseWithServer.tearDown(self)

    def test_interruptable_sync(self):
        """
        Test if Soledad can sync many smallfiles.
        """

        class _SyncInterruptor(threading.Thread):
            """
            A thread meant to interrupt the sync process.
            """
            
            def __init__(self, soledad, couchdb):
                self._soledad = soledad
                self._couchdb = couchdb
                threading.Thread.__init__(self)

            def run(self):
                while db._get_generation() < 2:
                    time.sleep(1)
                self._soledad.stop_sync()
                time.sleep(1)

        number_of_docs = 10
        self.startServer()

        # instantiate soledad and create a document
        sol = self._soledad_instance(
            # token is verified in test_target.make_token_soledad_app
            auth_token='auth-token'
        )
        _, doclist = sol.get_all_docs()
        self.assertEqual([], doclist)

        # create many small files
        for i in range(0, number_of_docs):
            sol.create_doc(json.loads(simple_doc))

        # ensure remote db exists before syncing
        db = CouchDatabase.open_database(
            urljoin(self._couch_url, 'user-user-uuid'),
            create=True,
            ensure_ddocs=True)

        # create interruptor thread
        t = _SyncInterruptor(sol, db)
        t.start()

        # sync with server
        sol._server_url = self.getURL()
        sol.sync()  # this will be interrupted when couch db gen >= 2
        t.join()

        # recover the sync process
        sol.sync()

        gen, doclist = db.get_all_docs()
        self.assertEqual(number_of_docs, len(doclist))

        # delete remote database
        db.delete_database()
        db.close()
        sol.close()
