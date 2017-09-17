# -*- coding: utf-8 -*-
# test_sqlcipher.py
# Copyright (C) 2013-2016 LEAP
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

from uuid import uuid4

from testscenarios import TestWithScenarios

from leap.soledad.common.l2db import sync
from leap.soledad.common.l2db import vectorclock
from leap.soledad.common.l2db import errors

from leap.soledad.client.http_target import SoledadHTTPSyncTarget

from test_soledad import u1db_tests as tests
from test_soledad.util import SQLCIPHER_SCENARIOS
from test_soledad.util import make_soledad_app
from test_soledad.util import soledad_sync_target
from test_soledad.util import BaseSoledadTest


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

    def create_database(self, replica_uid, sync_role=None):
        if replica_uid == 'test' and sync_role is None:
            # created up the chain by base class but unused
            return None
        db = self.create_database_for_role(replica_uid, sync_role)
        if sync_role:
            self._use_tracking[db] = (replica_uid, sync_role)
        self.addCleanup(db.close)
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

    def copy_database(self, db, sync_role=None):
        # DO NOT COPY OR REUSE THIS CODE OUTSIDE TESTS: COPYING U1DB DATABASES
        # IS THE WRONG THING TO DO, THE ONLY REASON WE DO SO HERE IS TO TEST
        # THAT WE CORRECTLY DETECT IT HAPPENING SO THAT WE CAN RAISE ERRORS
        # RATHER THAN CORRUPT USER DATA. USE SYNC INSTEAD, OR WE WILL SEND
        # NINJA TO YOUR HOUSE.
        db_copy = tests.DatabaseBaseTests.copy_database(self, db)
        name, orig_sync_role = self._use_tracking[db]
        self._use_tracking[db_copy] = (name + '(copy)', sync_role or
                                       orig_sync_role)
        return db_copy

    def test_sync_tracks_db_generation_of_other(self):
        self.db1 = self.create_database('test1', 'source')
        self.db2 = self.create_database('test2', 'target')
        self.assertEqual(0, self.sync(self.db1, self.db2))
        self.assertEqual(
            (0, ''), self.db1._get_replica_gen_and_trans_id('test2'))
        self.assertEqual(
            (0, ''), self.db2._get_replica_gen_and_trans_id('test1'))
        self.assertLastExchangeLog(self.db2,
                                   {'receive':
                                       {'docs': [], 'last_known_gen': 0},
                                    'return':
                                       {'docs': [], 'last_gen': 0}})

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

    def test_sync_pulling_doesnt_update_other_if_changed(self):
        self.db1 = self.create_database('test1', 'source')
        self.db2 = self.create_database('test2', 'target')
        doc = self.db2.create_doc_from_json(tests.simple_doc)
        # After the local side has sent its list of docs, before we start
        # receiving the "targets" response, we update the local database with a
        # new record.
        # When we finish synchronizing, we can notice that something locally
        # was updated, and we cannot tell c2 our new updated generation

        def before_get_docs(state):
            if state != 'before get_docs':
                return
            self.db1.create_doc_from_json(tests.simple_doc)

        self.assertEqual(0, self.sync(self.db1, self.db2,
                                      trace_hook=before_get_docs))
        self.assertLastExchangeLog(self.db2,
                                   {'receive':
                                       {'docs': [], 'last_known_gen': 0},
                                    'return':
                                       {'docs': [(doc.doc_id, doc.rev)],
                                        'last_gen': 1}})
        self.assertEqual(1, self.db1._get_replica_gen_and_trans_id('test2')[0])
        # c2 should not have gotten a '_record_sync_info' call, because the
        # local database had been updated more than just by the messages
        # returned from c2.
        self.assertEqual(
            (0, ''), self.db2._get_replica_gen_and_trans_id('test1'))

    def test_sync_doesnt_update_other_if_nothing_pulled(self):
        self.db1 = self.create_database('test1', 'source')
        self.db2 = self.create_database('test2', 'target')
        self.db1.create_doc_from_json(tests.simple_doc)

        def no_record_sync_info(state):
            if state != 'record_sync_info':
                return
            self.fail('SyncTarget.record_sync_info was called')
        self.assertEqual(1, self.sync(self.db1, self.db2,
                                      trace_hook_shallow=no_record_sync_info))
        self.assertEqual(
            1,
            self.db2._get_replica_gen_and_trans_id(self.db1._replica_uid)[0])

    def test_sync_ignores_convergence(self):
        self.db1 = self.create_database('test1', 'source')
        self.db2 = self.create_database('test2', 'both')
        doc = self.db1.create_doc_from_json(tests.simple_doc)
        self.db3 = self.create_database('test3', 'target')
        self.assertEqual(1, self.sync(self.db1, self.db3))
        self.assertEqual(0, self.sync(self.db2, self.db3))
        self.assertEqual(1, self.sync(self.db1, self.db2))
        self.assertLastExchangeLog(self.db2,
                                   {'receive':
                                       {'docs': [(doc.doc_id, doc.rev)],
                                        'source_uid': 'test1',
                                        'source_gen': 1, 'last_known_gen': 0},
                                    'return': {'docs': [], 'last_gen': 1}})

    def test_sync_ignores_superseded(self):
        self.db1 = self.create_database('test1', 'both')
        self.db2 = self.create_database('test2', 'both')
        doc = self.db1.create_doc_from_json(tests.simple_doc)
        doc_rev1 = doc.rev
        self.db3 = self.create_database('test3', 'target')
        self.sync(self.db1, self.db3)
        self.sync(self.db2, self.db3)
        new_content = '{"key": "altval"}'
        doc.set_json(new_content)
        self.db1.put_doc(doc)
        doc_rev2 = doc.rev
        self.sync(self.db2, self.db1)
        self.assertLastExchangeLog(self.db1,
                                   {'receive':
                                       {'docs': [(doc.doc_id, doc_rev1)],
                                        'source_uid': 'test2',
                                        'source_gen': 1, 'last_known_gen': 0},
                                    'return':
                                       {'docs': [(doc.doc_id, doc_rev2)],
                                        'last_gen': 2}})
        self.assertGetDoc(self.db1, doc.doc_id, doc_rev2, new_content, False)

    def test_sync_sees_remote_conflicted(self):
        self.db1 = self.create_database('test1', 'source')
        self.db2 = self.create_database('test2', 'target')
        doc1 = self.db1.create_doc_from_json(tests.simple_doc)
        doc_id = doc1.doc_id
        doc1_rev = doc1.rev
        self.db1.create_index('test-idx', 'key')
        new_doc = '{"key": "altval"}'
        doc2 = self.db2.create_doc_from_json(new_doc, doc_id=doc_id)
        doc2_rev = doc2.rev
        self.assertTransactionLog([doc1.doc_id], self.db1)
        self.sync(self.db1, self.db2)
        self.assertLastExchangeLog(self.db2,
                                   {'receive':
                                       {'docs': [(doc_id, doc1_rev)],
                                        'source_uid': 'test1',
                                        'source_gen': 1, 'last_known_gen': 0},
                                    'return':
                                       {'docs': [(doc_id, doc2_rev)],
                                        'last_gen': 1}})
        self.assertTransactionLog([doc_id, doc_id], self.db1)
        self.assertGetDoc(self.db1, doc_id, doc2_rev, new_doc, True)
        self.assertGetDoc(self.db2, doc_id, doc2_rev, new_doc, False)
        from_idx = self.db1.get_from_index('test-idx', 'altval')[0]
        self.assertEqual(doc2.doc_id, from_idx.doc_id)
        self.assertEqual(doc2.rev, from_idx.rev)
        self.assertTrue(from_idx.has_conflicts)
        self.assertEqual([], self.db1.get_from_index('test-idx', 'value'))

    def test_sync_sees_remote_delete_conflicted(self):
        self.db1 = self.create_database('test1', 'source')
        self.db2 = self.create_database('test2', 'target')
        doc1 = self.db1.create_doc_from_json(tests.simple_doc)
        doc_id = doc1.doc_id
        self.db1.create_index('test-idx', 'key')
        self.sync(self.db1, self.db2)
        doc2 = self.make_document(doc1.doc_id, doc1.rev, doc1.get_json())
        new_doc = '{"key": "altval"}'
        doc1.set_json(new_doc)
        self.db1.put_doc(doc1)
        self.db2.delete_doc(doc2)
        self.assertTransactionLog([doc_id, doc_id], self.db1)
        self.sync(self.db1, self.db2)
        self.assertLastExchangeLog(self.db2,
                                   {'receive':
                                       {'docs': [(doc_id, doc1.rev)],
                                        'source_uid': 'test1',
                                        'source_gen': 2, 'last_known_gen': 1},
                                    'return': {'docs': [(doc_id, doc2.rev)],
                                               'last_gen': 2}})
        self.assertTransactionLog([doc_id, doc_id, doc_id], self.db1)
        self.assertGetDocIncludeDeleted(self.db1, doc_id, doc2.rev, None, True)
        self.assertGetDocIncludeDeleted(
            self.db2, doc_id, doc2.rev, None, False)
        self.assertEqual([], self.db1.get_from_index('test-idx', 'value'))

    def test_sync_local_race_conflicted(self):
        self.db1 = self.create_database('test1', 'source')
        self.db2 = self.create_database('test2', 'target')
        doc = self.db1.create_doc_from_json(tests.simple_doc)
        doc_id = doc.doc_id
        doc1_rev = doc.rev
        self.db1.create_index('test-idx', 'key')
        self.sync(self.db1, self.db2)
        content1 = '{"key": "localval"}'
        content2 = '{"key": "altval"}'
        doc.set_json(content2)
        self.db2.put_doc(doc)
        doc2_rev2 = doc.rev
        triggered = []

        def after_whatschanged(state):
            if state != 'after whats_changed':
                return
            triggered.append(True)
            doc = self.make_document(doc_id, doc1_rev, content1)
            self.db1.put_doc(doc)

        self.sync(self.db1, self.db2, trace_hook=after_whatschanged)
        self.assertEqual([True], triggered)
        self.assertGetDoc(self.db1, doc_id, doc2_rev2, content2, True)
        from_idx = self.db1.get_from_index('test-idx', 'altval')[0]
        self.assertEqual(doc.doc_id, from_idx.doc_id)
        self.assertEqual(doc.rev, from_idx.rev)
        self.assertTrue(from_idx.has_conflicts)
        self.assertEqual([], self.db1.get_from_index('test-idx', 'value'))
        self.assertEqual([], self.db1.get_from_index('test-idx', 'localval'))

    def test_sync_propagates_deletes(self):
        self.db1 = self.create_database('test1', 'source')
        self.db2 = self.create_database('test2', 'both')
        doc1 = self.db1.create_doc_from_json(tests.simple_doc)
        doc_id = doc1.doc_id
        self.db1.create_index('test-idx', 'key')
        self.sync(self.db1, self.db2)
        self.db2.create_index('test-idx', 'key')
        self.db3 = self.create_database('test3', 'target')
        self.sync(self.db1, self.db3)
        self.db1.delete_doc(doc1)
        deleted_rev = doc1.rev
        self.sync(self.db1, self.db2)
        self.assertLastExchangeLog(self.db2,
                                   {'receive':
                                       {'docs': [(doc_id, deleted_rev)],
                                        'source_uid': 'test1',
                                        'source_gen': 2, 'last_known_gen': 1},
                                    'return': {'docs': [], 'last_gen': 2}})
        self.assertGetDocIncludeDeleted(
            self.db1, doc_id, deleted_rev, None, False)
        self.assertGetDocIncludeDeleted(
            self.db2, doc_id, deleted_rev, None, False)
        self.assertEqual([], self.db1.get_from_index('test-idx', 'value'))
        self.assertEqual([], self.db2.get_from_index('test-idx', 'value'))
        self.sync(self.db2, self.db3)
        self.assertLastExchangeLog(self.db3,
                                   {'receive':
                                       {'docs': [(doc_id, deleted_rev)],
                                        'source_uid': 'test2',
                                        'source_gen': 2,
                                        'last_known_gen': 0},
                                    'return':
                                       {'docs': [], 'last_gen': 2}})
        self.assertGetDocIncludeDeleted(
            self.db3, doc_id, deleted_rev, None, False)

    def test_sync_propagates_deletes_2(self):
        self.db1 = self.create_database('test1', 'source')
        self.db2 = self.create_database('test2', 'target')
        self.db1.create_doc_from_json('{"a": "1"}', doc_id='the-doc')
        self.sync(self.db1, self.db2)
        doc1_2 = self.db2.get_doc('the-doc')
        self.db2.delete_doc(doc1_2)
        self.sync(self.db1, self.db2)
        self.assertGetDocIncludeDeleted(
            self.db1, 'the-doc', doc1_2.rev, None, False)

    def test_sync_detects_identical_replica_uid(self):
        self.db1 = self.create_database('test1', 'source')
        self.db2 = self.create_database('test1', 'target')
        self.db1.create_doc_from_json(tests.simple_doc, doc_id='doc1')
        self.assertRaises(
            errors.InvalidReplicaUID, self.sync, self.db1, self.db2)

    def test_optional_sync_preserve_json(self):
        self.db1 = self.create_database('test1', 'source')
        self.db2 = self.create_database('test2', 'target')
        cont1 = '{  "a":  2  }'
        cont2 = '{ "b":3}'
        self.db1.create_doc_from_json(cont1, doc_id="1")
        self.db2.create_doc_from_json(cont2, doc_id="2")
        self.sync(self.db1, self.db2)
        self.assertEqual(cont1, self.db2.get_doc("1").get_json())
        self.assertEqual(cont2, self.db1.get_doc("2").get_json())

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

    def test_sync_pulls_changes(self):
        self.db1 = self.create_database('test1', 'source')
        self.db2 = self.create_database('test2', 'target')
        doc = self.db2.create_doc_from_json(tests.simple_doc)
        self.db1.create_index('test-idx', 'key')
        self.assertEqual(0, self.sync(self.db1, self.db2))
        self.assertGetDoc(self.db1, doc.doc_id, doc.rev,
                          tests.simple_doc, False)
        self.assertEqual(1, self.db1._get_replica_gen_and_trans_id('test2')[0])
        self.assertEqual(1, self.db2._get_replica_gen_and_trans_id('test1')[0])
        self.assertLastExchangeLog(self.db2,
                                   {'receive':
                                       {'docs': [], 'last_known_gen': 0},
                                    'return':
                                       {'docs': [(doc.doc_id, doc.rev)],
                                        'last_gen': 1}})
        self.assertEqual([doc], self.db1.get_from_index('test-idx', 'value'))

    def test_sync_supersedes_conflicts(self):
        self.db1 = self.create_database('test1', 'both')
        self.db2 = self.create_database('test2', 'target')
        self.db3 = self.create_database('test3', 'both')
        doc1 = self.db1.create_doc_from_json('{"a": 1}', doc_id='the-doc')
        self.db2.create_doc_from_json('{"b": 1}', doc_id='the-doc')
        self.db3.create_doc_from_json('{"c": 1}', doc_id='the-doc')
        self.sync(self.db3, self.db1)
        self.assertEqual(
            self.db1._get_generation_info(),
            self.db3._get_replica_gen_and_trans_id(self.db1._replica_uid))
        self.assertEqual(
            self.db3._get_generation_info(),
            self.db1._get_replica_gen_and_trans_id(self.db3._replica_uid))
        self.sync(self.db3, self.db2)
        self.assertEqual(
            self.db2._get_generation_info(),
            self.db3._get_replica_gen_and_trans_id(self.db2._replica_uid))
        self.assertEqual(
            self.db3._get_generation_info(),
            self.db2._get_replica_gen_and_trans_id(self.db3._replica_uid))
        self.assertEqual(3, len(self.db3.get_doc_conflicts('the-doc')))
        doc1.set_json('{"a": 2}')
        self.db1.put_doc(doc1)
        self.sync(self.db3, self.db1)
        # original doc1 should have been removed from conflicts
        self.assertEqual(3, len(self.db3.get_doc_conflicts('the-doc')))

    def test_sync_stops_after_get_sync_info(self):
        self.db1 = self.create_database('test1', 'source')
        self.db2 = self.create_database('test2', 'target')
        self.db1.create_doc_from_json(tests.simple_doc)
        self.sync(self.db1, self.db2)

        def put_hook(state):
            self.fail("Tracehook triggered for %s" % (state,))

        self.sync(self.db1, self.db2, trace_hook_shallow=put_hook)

    def test_sync_detects_rollback_in_source(self):
        self.db1 = self.create_database('test1', 'source')
        self.db2 = self.create_database('test2', 'target')
        self.db1.create_doc_from_json(tests.simple_doc, doc_id='doc1')
        self.sync(self.db1, self.db2)
        self.db1_copy = self.copy_database(self.db1)
        self.db1.create_doc_from_json(tests.simple_doc, doc_id='doc2')
        self.sync(self.db1, self.db2)
        self.assertRaises(
            errors.InvalidGeneration, self.sync, self.db1_copy, self.db2)

    def test_sync_detects_rollback_in_target(self):
        self.db1 = self.create_database('test1', 'source')
        self.db2 = self.create_database('test2', 'target')
        self.db1.create_doc_from_json(tests.simple_doc, doc_id="divergent")
        self.sync(self.db1, self.db2)
        self.db2_copy = self.copy_database(self.db2)
        self.db2.create_doc_from_json(tests.simple_doc, doc_id='doc2')
        self.sync(self.db1, self.db2)
        self.assertRaises(
            errors.InvalidGeneration, self.sync, self.db1, self.db2_copy)

    def test_sync_detects_diverged_source(self):
        self.db1 = self.create_database('test1', 'source')
        self.db2 = self.create_database('test2', 'target')
        self.db3 = self.copy_database(self.db1)
        self.db1.create_doc_from_json(tests.simple_doc, doc_id="divergent")
        self.db3.create_doc_from_json(tests.simple_doc, doc_id="divergent")
        self.sync(self.db1, self.db2)
        self.assertRaises(
            errors.InvalidTransactionId, self.sync, self.db3, self.db2)

    def test_sync_detects_diverged_target(self):
        self.db1 = self.create_database('test1', 'source')
        self.db2 = self.create_database('test2', 'target')
        self.db3 = self.copy_database(self.db2)
        self.db3.create_doc_from_json(tests.nested_doc, doc_id="divergent")
        self.db1.create_doc_from_json(tests.simple_doc, doc_id="divergent")
        self.sync(self.db1, self.db2)
        self.assertRaises(
            errors.InvalidTransactionId, self.sync, self.db1, self.db3)

    def test_sync_detects_rollback_and_divergence_in_source(self):
        self.db1 = self.create_database('test1', 'source')
        self.db2 = self.create_database('test2', 'target')
        self.db1.create_doc_from_json(tests.simple_doc, doc_id='doc1')
        self.sync(self.db1, self.db2)
        self.db1_copy = self.copy_database(self.db1)
        self.db1.create_doc_from_json(tests.simple_doc, doc_id='doc2')
        self.db1.create_doc_from_json(tests.simple_doc, doc_id='doc3')
        self.sync(self.db1, self.db2)
        self.db1_copy.create_doc_from_json(tests.simple_doc, doc_id='doc2')
        self.db1_copy.create_doc_from_json(tests.simple_doc, doc_id='doc3')
        self.assertRaises(
            errors.InvalidTransactionId, self.sync, self.db1_copy, self.db2)

    def test_sync_detects_rollback_and_divergence_in_target(self):
        self.db1 = self.create_database('test1', 'source')
        self.db2 = self.create_database('test2', 'target')
        self.db1.create_doc_from_json(tests.simple_doc, doc_id="divergent")
        self.sync(self.db1, self.db2)
        self.db2_copy = self.copy_database(self.db2)
        self.db2.create_doc_from_json(tests.simple_doc, doc_id='doc2')
        self.db2.create_doc_from_json(tests.simple_doc, doc_id='doc3')
        self.sync(self.db1, self.db2)
        self.db2_copy.create_doc_from_json(tests.simple_doc, doc_id='doc2')
        self.db2_copy.create_doc_from_json(tests.simple_doc, doc_id='doc3')
        self.assertRaises(
            errors.InvalidTransactionId, self.sync, self.db1, self.db2_copy)


def make_local_db_and_soledad_target(
        test, path='test',
        source_replica_uid=uuid4().hex):
    test.startTwistedServer()
    replica_uid = os.path.basename(path)
    db = test.request_state._create_database(replica_uid)
    st = soledad_sync_target(
        test, db._dbname,
        source_replica_uid=source_replica_uid)
    return db, st


target_scenarios = [
    ('leap', {
        'create_db_and_target': make_local_db_and_soledad_target,
        'make_app_with_state': make_soledad_app,
        'do_sync': sync_via_synchronizer_and_soledad}),
]
