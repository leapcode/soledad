# -*- coding: utf-8 -*-
# test_sqlcipher.py
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
Test sqlcipher backend sync.
"""


import os
import simplejson as json
from u1db import (
    sync,
    vectorclock,
)

from testscenarios import TestWithScenarios
from urlparse import urljoin

from twisted.internet import defer

from leap.soledad.common import couch
from leap.soledad.common.crypto import ENC_SCHEME_KEY
from leap.soledad.client.http_target import SoledadHTTPSyncTarget
from leap.soledad.client.crypto import decrypt_doc_dict
from leap.soledad.client.sqlcipher import (
    SQLCipherDatabase,
)

from leap.soledad.common.tests import u1db_tests as tests
from leap.soledad.common.tests.test_sqlcipher import SQLCIPHER_SCENARIOS
from leap.soledad.common.tests.util import make_soledad_app
from leap.soledad.common.tests.util import soledad_sync_target
from leap.soledad.common.tests.util import BaseSoledadTest
from leap.soledad.common.tests.util import SoledadWithCouchServerMixin


# -----------------------------------------------------------------------------
# The following tests come from `u1db.tests.test_sync`.
# -----------------------------------------------------------------------------

def sync_via_synchronizer_and_soledad(test, db_source, db_target,
                                      trace_hook=None,
                                      trace_hook_shallow=None):
    if trace_hook:
        test.skipTest("full trace hook unsupported over http")
    path = test._http_at[db_target]
    target = SoledadHTTPSyncTarget.connect(
        test.getURL(path), test._soledad._crypto)
    target.set_token_credentials('user-uuid', 'auth-token')
    if trace_hook_shallow:
        target._set_trace_hook_shallow(trace_hook_shallow)
    return sync.Synchronizer(db_source, target).sync()


def sync_via_synchronizer(test, db_source, db_target,
                          trace_hook=None,
                          trace_hook_shallow=None):
    target = db_target.get_sync_target()
    trace_hook = trace_hook or trace_hook_shallow
    if trace_hook:
        target._set_trace_hook(trace_hook)
    return sync.Synchronizer(db_source, target).sync()


sync_scenarios = []
for name, scenario in SQLCIPHER_SCENARIOS:
    scenario['do_sync'] = sync_via_synchronizer
    sync_scenarios.append((name, scenario))


class SQLCipherDatabaseSyncTests(
        TestWithScenarios,
        tests.DatabaseBaseTests,
        BaseSoledadTest):

    """
    Test for succesfull sync between SQLCipher and LeapBackend.

    Some of the tests in this class had to be adapted because the remote
    backend always receive encrypted content, and so it can not rely on
    document's content comparison to try to autoresolve conflicts.
    """

    scenarios = sync_scenarios

    def setUp(self):
        self._use_tracking = {}
        super(tests.DatabaseBaseTests, self).setUp()

    def tearDown(self):
        super(tests.DatabaseBaseTests, self).tearDown()
        if hasattr(self, 'db1') and isinstance(self.db1, SQLCipherDatabase):
            self.db1.close()
        if hasattr(self, 'db1_copy') \
                and isinstance(self.db1_copy, SQLCipherDatabase):
            self.db1_copy.close()
        if hasattr(self, 'db2') \
                and isinstance(self.db2, SQLCipherDatabase):
            self.db2.close()
        if hasattr(self, 'db2_copy') \
                and isinstance(self.db2_copy, SQLCipherDatabase):
            self.db2_copy.close()
        if hasattr(self, 'db3') \
                and isinstance(self.db3, SQLCipherDatabase):
            self.db3.close()

    def create_database(self, replica_uid, sync_role=None):
        if replica_uid == 'test' and sync_role is None:
            # created up the chain by base class but unused
            return None
        db = self.create_database_for_role(replica_uid, sync_role)
        if sync_role:
            self._use_tracking[db] = (replica_uid, sync_role)
        return db

    def create_database_for_role(self, replica_uid, sync_role):
        # hook point for reuse
        return tests.DatabaseBaseTests.create_database(self, replica_uid)

    def sync(self, db_from, db_to, trace_hook=None,
             trace_hook_shallow=None):
        from_name, from_sync_role = self._use_tracking[db_from]
        to_name, to_sync_role = self._use_tracking[db_to]
        if from_sync_role not in ('source', 'both'):
            raise Exception("%s marked for %s use but used as source" %
                            (from_name, from_sync_role))
        if to_sync_role not in ('target', 'both'):
            raise Exception("%s marked for %s use but used as target" %
                            (to_name, to_sync_role))
        return self.do_sync(self, db_from, db_to, trace_hook,
                            trace_hook_shallow)

    def assertLastExchangeLog(self, db, expected):
        log = getattr(db, '_last_exchange_log', None)
        if log is None:
            return
        self.assertEqual(expected, log)

    def test_sync_autoresolves(self):
        """
        Test for sync autoresolve remote.

        This test was adapted because the remote database receives encrypted
        content and so it can't compare documents contents to autoresolve.
        """
        # The remote database can't autoresolve conflicts based on magic
        # content convergence, so we modify this test to leave the possibility
        # of the remode document ending up in conflicted state.
        self.db1 = self.create_database('test1', 'source')
        self.db2 = self.create_database('test2', 'target')
        doc1 = self.db1.create_doc_from_json(tests.simple_doc, doc_id='doc')
        rev1 = doc1.rev
        doc2 = self.db2.create_doc_from_json(tests.simple_doc, doc_id='doc')
        rev2 = doc2.rev
        self.sync(self.db1, self.db2)
        doc = self.db1.get_doc('doc')
        self.assertFalse(doc.has_conflicts)
        # if remote content is in conflicted state, then document revisions
        # will be different.
        # self.assertEqual(doc.rev, self.db2.get_doc('doc').rev)
        v = vectorclock.VectorClockRev(doc.rev)
        self.assertTrue(v.is_newer(vectorclock.VectorClockRev(rev1)))
        self.assertTrue(v.is_newer(vectorclock.VectorClockRev(rev2)))

    def test_sync_autoresolves_moar(self):
        """
        Test for sync autoresolve local.

        This test was adapted to decrypt remote content before assert.
        """
        # here we test that when a database that has a conflicted document is
        # the source of a sync, and the target database has a revision of the
        # conflicted document that is newer than the source database's, and
        # that target's database's document's content is the same as the
        # source's document's conflict's, the source's document's conflict gets
        # autoresolved, and the source's document's revision bumped.
        #
        # idea is as follows:
        # A          B
        # a1         -
        #   `------->
        # a1         a1
        # v          v
        # a2         a1b1
        #   `------->
        # a1b1+a2    a1b1
        #            v
        # a1b1+a2    a1b2 (a1b2 has same content as a2)
        #   `------->
        # a3b2       a1b2 (autoresolved)
        #   `------->
        # a3b2       a3b2
        self.db1 = self.create_database('test1', 'source')
        self.db2 = self.create_database('test2', 'target')
        self.db1.create_doc_from_json(tests.simple_doc, doc_id='doc')
        self.sync(self.db1, self.db2)
        for db, content in [(self.db1, '{}'), (self.db2, '{"hi": 42}')]:
            doc = db.get_doc('doc')
            doc.set_json(content)
            db.put_doc(doc)
        self.sync(self.db1, self.db2)
        # db1 and db2 now both have a doc of {hi:42}, but db1 has a conflict
        doc = self.db1.get_doc('doc')
        rev1 = doc.rev
        self.assertTrue(doc.has_conflicts)
        # set db2 to have a doc of {} (same as db1 before the conflict)
        doc = self.db2.get_doc('doc')
        doc.set_json('{}')
        self.db2.put_doc(doc)
        rev2 = doc.rev
        # sync it across
        self.sync(self.db1, self.db2)
        # tadaa!
        doc = self.db1.get_doc('doc')
        self.assertFalse(doc.has_conflicts)
        vec1 = vectorclock.VectorClockRev(rev1)
        vec2 = vectorclock.VectorClockRev(rev2)
        vec3 = vectorclock.VectorClockRev(doc.rev)
        self.assertTrue(vec3.is_newer(vec1))
        self.assertTrue(vec3.is_newer(vec2))
        # because the conflict is on the source, sync it another time
        self.sync(self.db1, self.db2)
        # make sure db2 now has the exact same thing
        doc1 = self.db1.get_doc('doc')
        self.assertGetEncryptedDoc(
            self.db2,
            doc1.doc_id, doc1.rev, doc1.get_json(), False)

    def test_sync_autoresolves_moar_backwards(self):
        # here we would test that when a database that has a conflicted
        # document is the target of a sync, and the source database has a
        # revision of the conflicted document that is newer than the target
        # database's, and that source's database's document's content is the
        # same as the target's document's conflict's, the target's document's
        # conflict gets autoresolved, and the document's revision bumped.
        #
        # Despite that, in Soledad we suppose that the server never syncs, so
        # it never has conflicted documents. Also, if it had, convergence
        # would not be possible by checking document's contents because they
        # would be encrypted in server.
        #
        # Therefore we suppress this test.
        pass

    def test_sync_autoresolves_moar_backwards_three(self):
        # here we would test that when a database that has a conflicted
        # document is the target of a sync, and the source database has a
        # revision of the conflicted document that is newer than the target
        # database's, and that source's database's document's content is the
        # same as the target's document's conflict's, the target's document's
        # conflict gets autoresolved, and the document's revision bumped.
        #
        # We use the same reasoning from the last test to suppress this one.
        pass

    def test_sync_propagates_resolution(self):
        """
        Test if synchronization propagates resolution.

        This test was adapted to decrypt remote content before assert.
        """
        self.db1 = self.create_database('test1', 'both')
        self.db2 = self.create_database('test2', 'both')
        doc1 = self.db1.create_doc_from_json('{"a": 1}', doc_id='the-doc')
        db3 = self.create_database('test3', 'both')
        self.sync(self.db2, self.db1)
        self.assertEqual(
            self.db1._get_generation_info(),
            self.db2._get_replica_gen_and_trans_id(self.db1._replica_uid))
        self.assertEqual(
            self.db2._get_generation_info(),
            self.db1._get_replica_gen_and_trans_id(self.db2._replica_uid))
        self.sync(db3, self.db1)
        # update on 2
        doc2 = self.make_document('the-doc', doc1.rev, '{"a": 2}')
        self.db2.put_doc(doc2)
        self.sync(self.db2, db3)
        self.assertEqual(db3.get_doc('the-doc').rev, doc2.rev)
        # update on 1
        doc1.set_json('{"a": 3}')
        self.db1.put_doc(doc1)
        # conflicts
        self.sync(self.db2, self.db1)
        self.sync(db3, self.db1)
        self.assertTrue(self.db2.get_doc('the-doc').has_conflicts)
        self.assertTrue(db3.get_doc('the-doc').has_conflicts)
        # resolve
        conflicts = self.db2.get_doc_conflicts('the-doc')
        doc4 = self.make_document('the-doc', None, '{"a": 4}')
        revs = [doc.rev for doc in conflicts]
        self.db2.resolve_doc(doc4, revs)
        doc2 = self.db2.get_doc('the-doc')
        self.assertEqual(doc4.get_json(), doc2.get_json())
        self.assertFalse(doc2.has_conflicts)
        self.sync(self.db2, db3)
        doc3 = db3.get_doc('the-doc')
        if ENC_SCHEME_KEY in doc3.content:
            _crypto = self._soledad._crypto
            key = _crypto.doc_passphrase(doc3.doc_id)
            secret = _crypto.secret
            doc3.set_json(decrypt_doc_dict(
                doc3.content,
                doc3.doc_id, doc3.rev, key, secret))
        self.assertEqual(doc4.get_json(), doc3.get_json())
        self.assertFalse(doc3.has_conflicts)
        self.db1.close()
        self.db2.close()
        db3.close()

    def test_sync_puts_changes(self):
        """
        Test if sync puts changes in remote replica.

        This test was adapted to decrypt remote content before assert.
        """
        self.db1 = self.create_database('test1', 'source')
        self.db2 = self.create_database('test2', 'target')
        doc = self.db1.create_doc_from_json(tests.simple_doc)
        self.assertEqual(1, self.sync(self.db1, self.db2))
        self.assertGetEncryptedDoc(
            self.db2, doc.doc_id, doc.rev, tests.simple_doc, False)
        self.assertEqual(1, self.db1._get_replica_gen_and_trans_id('test2')[0])
        self.assertEqual(1, self.db2._get_replica_gen_and_trans_id('test1')[0])
        self.assertLastExchangeLog(
            self.db2,
            {'receive': {'docs': [(doc.doc_id, doc.rev)],
                         'source_uid': 'test1',
                         'source_gen': 1, 'last_known_gen': 0},
             'return': {'docs': [], 'last_gen': 1}})


def _make_local_db_and_token_http_target(test, path='test'):
    test.startTwistedServer()
    # ensure remote db exists before syncing
    db = couch.CouchDatabase.open_database(
        urljoin(test._couch_url, 'test'),
        create=True,
        ensure_ddocs=True)

    #db = test.request_state.open_database(os.path.basename(path))
    replica_uid = test._soledad._dbpool.replica_uid
    sync_db = test._soledad._sync_db
    sync_enc_pool = test._soledad._sync_enc_pool
    st = soledad_sync_target(
        test, path,
        source_replica_uid=replica_uid,
        sync_db=sync_db,
        sync_enc_pool=sync_enc_pool)
    return db, st

target_scenarios = [
    ('leap', {
        'create_db_and_target': _make_local_db_and_token_http_target,
        'make_app_with_state': make_soledad_app,
        'do_sync': sync_via_synchronizer_and_soledad}),
]


class SQLCipherSyncTargetTests(
        TestWithScenarios,
        tests.DatabaseBaseTests,
        tests.TestCaseWithServer,
        SoledadWithCouchServerMixin):

    scenarios = (tests.multiply_scenarios(SQLCIPHER_SCENARIOS,
                                          target_scenarios))

    whitebox = False

    def setUp(self):
        super(tests.DatabaseBaseTests, self).setUp()
        self.db, self.st = self.create_db_and_target(self)
        self.addCleanup(self.st.close)
        self.other_changes = []

    def tearDown(self):
        super(tests.DatabaseBaseTests, self).tearDown()

    def assertLastExchangeLog(self, db, expected):
        log = getattr(db, '_last_exchange_log', None)
        if log is None:
            return
        self.assertEqual(expected, log)

    def receive_doc(self, doc, gen, trans_id):
        self.other_changes.append(
            (doc.doc_id, doc.rev, doc.get_json(), gen, trans_id))

    def make_app(self):
        self.request_state = couch.CouchServerState(self._couch_url)
        return self.make_app_with_state(self.request_state)

    @defer.inlineCallbacks
    def test_sync_exchange(self):
        """
        Modified to account for possibly receiving encrypted documents from
        sever-side.
        """

        docs_by_gen = [
            (self.make_document('doc-id', 'replica:1', tests.simple_doc), 10,
             'T-sid')]
        new_gen, trans_id = yield self.st.sync_exchange(
            docs_by_gen, 'replica', last_known_generation=0,
            last_known_trans_id=None, insert_doc_cb=self.receive_doc)
        self.assertGetEncryptedDoc(
            self.db, 'doc-id', 'replica:1', tests.simple_doc, False)
        self.assertTransactionLog(['doc-id'], self.db)
        last_trans_id = self.getLastTransId(self.db)
        self.assertEqual(([], 1, last_trans_id),
                         (self.other_changes, new_gen, last_trans_id))
        sync_info = yield self.st.get_sync_info('replica')
        self.assertEqual(10, sync_info[3])

    @defer.inlineCallbacks
    def test_sync_exchange_push_many(self):
        """
        Modified to account for possibly receiving encrypted documents from
        sever-side.
        """
        docs_by_gen = [
            (self.make_document(
                'doc-id', 'replica:1', tests.simple_doc), 10, 'T-1'),
            (self.make_document('doc-id2', 'replica:1', tests.nested_doc), 11,
             'T-2')]
        new_gen, trans_id = yield self.st.sync_exchange(
            docs_by_gen, 'replica', last_known_generation=0,
            last_known_trans_id=None, insert_doc_cb=self.receive_doc)
        self.assertGetEncryptedDoc(
            self.db, 'doc-id', 'replica:1', tests.simple_doc, False)
        self.assertGetEncryptedDoc(
            self.db, 'doc-id2', 'replica:1', tests.nested_doc, False)
        self.assertTransactionLog(['doc-id', 'doc-id2'], self.db)
        last_trans_id = self.getLastTransId(self.db)
        self.assertEqual(([], 2, last_trans_id),
                         (self.other_changes, new_gen, trans_id))
        sync_info = yield self.st.get_sync_info('replica')
        self.assertEqual(11, sync_info[3])

    @defer.inlineCallbacks
    def test_sync_exchange_returns_many_new_docs(self):
        """
        Modified to account for JSON serialization differences.
        """
        doc = self.db.create_doc_from_json(tests.simple_doc)
        doc2 = self.db.create_doc_from_json(tests.nested_doc)
        self.assertTransactionLog([doc.doc_id, doc2.doc_id], self.db)
        new_gen, _ = yield self.st.sync_exchange(
            [], 'other-replica', last_known_generation=0,
            last_known_trans_id=None, insert_doc_cb=self.receive_doc)
        self.assertTransactionLog([doc.doc_id, doc2.doc_id], self.db)
        self.assertEqual(2, new_gen)
        self.assertEqual(
            [(doc.doc_id, doc.rev, 1),
             (doc2.doc_id, doc2.rev, 2)],
            [c[:2] + c[3:4] for c in self.other_changes])
        self.assertEqual(
            json.dumps(tests.simple_doc),
            json.dumps(self.other_changes[0][2]))
        self.assertEqual(
            json.loads(tests.nested_doc),
            json.loads(self.other_changes[1][2]))
        if self.whitebox:
            self.assertEqual(
                self.db._last_exchange_log['return'],
                {'last_gen': 2, 'docs':
                 [(doc.doc_id, doc.rev), (doc2.doc_id, doc2.rev)]})
