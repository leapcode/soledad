# -*- coding: utf-8 -*-
# test_sync_mutex.py
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
Test that synchronization is a critical section and, as such, there might not
be two concurrent synchronization processes at the same time.
"""


import pytest
import time
import uuid

from six.moves.urllib.parse import urljoin

from twisted.internet import defer

from leap.soledad.client.sync import SoledadSynchronizer

from leap.soledad.common.couch.state import CouchServerState
from leap.soledad.common.couch import CouchDatabase
from test_soledad.u1db_tests import TestCaseWithServer

from test_soledad.util import CouchDBTestCase
from test_soledad.util import BaseSoledadTest
from test_soledad.util import make_token_soledad_app
from test_soledad.util import make_soledad_document_for_test
from test_soledad.util import soledad_sync_target


# monkey-patch the soledad synchronizer so it stores start and finish times

_old_sync = SoledadSynchronizer.sync


def _timed_sync(self):
    t = time.time()

    sync_id = uuid.uuid4()

    if not getattr(self.source, 'sync_times', False):
        self.source.sync_times = {}

    self.source.sync_times[sync_id] = {'start': t}

    def _store_finish_time(passthrough):
        t = time.time()
        self.source.sync_times[sync_id]['end'] = t
        return passthrough

    d = _old_sync(self)
    d.addBoth(_store_finish_time)
    return d


SoledadSynchronizer.sync = _timed_sync

# -- end of monkey-patching


@pytest.mark.needs_couch
class TestSyncMutex(
        BaseSoledadTest, CouchDBTestCase, TestCaseWithServer):

    @staticmethod
    def make_app_with_state(state):
        return make_token_soledad_app(state)

    make_document_for_test = make_soledad_document_for_test

    sync_target = soledad_sync_target

    def make_app(self):
        self.request_state = CouchServerState(self.couch_url)
        return self.make_app_with_state(self.request_state)

    def setUp(self):
        TestCaseWithServer.setUp(self)
        CouchDBTestCase.setUp(self)
        self.user = ('user-%s' % uuid.uuid4().hex)

    def tearDown(self):
        CouchDBTestCase.tearDown(self)
        TestCaseWithServer.tearDown(self)

    def test_two_concurrent_syncs_do_not_overlap_no_docs(self):
        self.startServer()

        # ensure remote db exists before syncing
        db = CouchDatabase.open_database(
            urljoin(self.couch_url, 'user-' + self.user),
            create=True)

        sol = self._soledad_instance(
            user=self.user, server_url=self.getURL())

        d1 = sol.sync()
        d2 = sol.sync()

        def _assert_syncs_do_not_overlap(thearg):
            # recover sync times
            sync_times = []
            for key in sol._dbsyncer.sync_times:
                sync_times.append(sol._dbsyncer.sync_times[key])
            sync_times.sort(key=lambda s: s['start'])

            self.assertTrue(
                (sync_times[0]['start'] < sync_times[0]['end'] and
                 sync_times[0]['end'] < sync_times[1]['start'] and
                 sync_times[1]['start'] < sync_times[1]['end']))

            db.delete_database()
            db.close()
            sol.close()

        d = defer.gatherResults([d1, d2])
        d.addBoth(_assert_syncs_do_not_overlap)
        return d
