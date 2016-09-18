# -*- coding: utf-8 -*-
# test_sync_target.py
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
Test Leap backend bits: sync target
"""
import cStringIO
import os
import time
import json
import random
import string
import shutil
from uuid import uuid4

from testscenarios import TestWithScenarios
from twisted.internet import defer

from leap.soledad.client import http_target as target
from leap.soledad.client import crypto
from leap.soledad.client.sqlcipher import SQLCipherU1DBSync
from leap.soledad.client.sqlcipher import SQLCipherOptions
from leap.soledad.client.sqlcipher import SQLCipherDatabase

from leap.soledad.common import l2db

from leap.soledad.common.document import SoledadDocument
from test_soledad import u1db_tests as tests
from test_soledad.util import make_sqlcipher_database_for_test
from test_soledad.util import make_soledad_app
from test_soledad.util import make_token_soledad_app
from test_soledad.util import make_soledad_document_for_test
from test_soledad.util import soledad_sync_target
from test_soledad.util import SoledadWithCouchServerMixin
from test_soledad.util import ADDRESS
from test_soledad.util import SQLCIPHER_SCENARIOS


# -----------------------------------------------------------------------------
# The following tests come from `u1db.tests.test_remote_sync_target`.
# -----------------------------------------------------------------------------

class TestSoledadParseReceivedDocResponse(SoledadWithCouchServerMixin):

    """
    Some tests had to be copied to this class so we can instantiate our own
    target.
    """

    def setUp(self):
        SoledadWithCouchServerMixin.setUp(self)
        creds = {'token': {
            'uuid': 'user-uuid',
            'token': 'auth-token',
        }}
        self.target = target.SoledadHTTPSyncTarget(
            self.couch_url,
            uuid4().hex,
            creds,
            self._soledad._crypto,
            None)

    def tearDown(self):
        self.target.close()
        SoledadWithCouchServerMixin.tearDown(self)

    def test_extra_comma(self):
        """
        Test adapted to use encrypted content.
        """
        doc = SoledadDocument('i', rev='r')
        doc.content = {}
        _crypto = self._soledad._crypto
        key = _crypto.doc_passphrase(doc.doc_id)
        secret = _crypto.secret

        enc_json = crypto.encrypt_docstr(
            doc.get_json(), doc.doc_id, doc.rev,
            key, secret)

        with self.assertRaises(l2db.errors.BrokenSyncStream):
            self.target._parse_received_doc_response("[\r\n{},\r\n]")

        with self.assertRaises(l2db.errors.BrokenSyncStream):
            self.target._parse_received_doc_response(
                ('[\r\n{},\r\n{"id": "i", "rev": "r", ' +
                 '"content": %s, "gen": 3, "trans_id": "T-sid"}' +
                 ',\r\n]') % json.dumps(enc_json))

    def test_wrong_start(self):
        with self.assertRaises(l2db.errors.BrokenSyncStream):
            self.target._parse_received_doc_response("{}\r\n]")

        with self.assertRaises(l2db.errors.BrokenSyncStream):
            self.target._parse_received_doc_response("\r\n{}\r\n]")

        with self.assertRaises(l2db.errors.BrokenSyncStream):
            self.target._parse_received_doc_response("")

    def test_wrong_end(self):
        with self.assertRaises(l2db.errors.BrokenSyncStream):
            self.target._parse_received_doc_response("[\r\n{}")

        with self.assertRaises(l2db.errors.BrokenSyncStream):
            self.target._parse_received_doc_response("[\r\n")

    def test_missing_comma(self):
        with self.assertRaises(l2db.errors.BrokenSyncStream):
            self.target._parse_received_doc_response(
                '[\r\n{}\r\n{"id": "i", "rev": "r", '
                '"content": "c", "gen": 3}\r\n]')

    def test_no_entries(self):
        with self.assertRaises(l2db.errors.BrokenSyncStream):
            self.target._parse_received_doc_response("[\r\n]")

    def test_error_in_stream(self):
        with self.assertRaises(l2db.errors.BrokenSyncStream):
            self.target._parse_received_doc_response(
                '[\r\n{"new_generation": 0},'
                '\r\n{"error": "unavailable"}\r\n')

        with self.assertRaises(l2db.errors.BrokenSyncStream):
            self.target._parse_received_doc_response(
                '[\r\n{"error": "unavailable"}\r\n')

        with self.assertRaises(l2db.errors.BrokenSyncStream):
            self.target._parse_received_doc_response('[\r\n{"error": "?"}\r\n')

#
# functions for TestRemoteSyncTargets
#


def make_local_db_and_soledad_target(
        test, path='test',
        source_replica_uid=uuid4().hex):
    test.startTwistedServer()
    replica_uid = os.path.basename(path)
    db = test.request_state._create_database(replica_uid)
    sync_db = test._soledad._sync_db
    sync_enc_pool = test._soledad._sync_enc_pool
    st = soledad_sync_target(
        test, db._dbname,
        source_replica_uid=source_replica_uid,
        sync_db=sync_db,
        sync_enc_pool=sync_enc_pool)
    return db, st


def make_local_db_and_token_soledad_target(
        test,
        source_replica_uid=uuid4().hex):
    db, st = make_local_db_and_soledad_target(
        test, path='test',
        source_replica_uid=source_replica_uid)
    st.set_token_credentials('user-uuid', 'auth-token')
    return db, st


class TestSoledadSyncTarget(
        TestWithScenarios,
        SoledadWithCouchServerMixin,
        tests.TestCaseWithServer):

    scenarios = [
        ('token_soledad',
            {'make_app_with_state': make_token_soledad_app,
             'make_document_for_test': make_soledad_document_for_test,
             'create_db_and_target': make_local_db_and_token_soledad_target,
             'make_database_for_test': make_sqlcipher_database_for_test,
             'sync_target': soledad_sync_target}),
    ]

    def getSyncTarget(self, path=None, source_replica_uid=uuid4().hex):
        if self.port is None:
            self.startTwistedServer()
        sync_db = self._soledad._sync_db
        sync_enc_pool = self._soledad._sync_enc_pool
        if path is None:
            path = self.db2._dbname
        target = self.sync_target(
            self, path,
            source_replica_uid=source_replica_uid,
            sync_db=sync_db,
            sync_enc_pool=sync_enc_pool)
        self.addCleanup(target.close)
        return target

    def setUp(self):
        TestWithScenarios.setUp(self)
        SoledadWithCouchServerMixin.setUp(self)
        self.startTwistedServer()
        self.db1 = make_sqlcipher_database_for_test(self, 'test1')
        self.db2 = self.request_state._create_database('test')

    def tearDown(self):
        # db2, _ = self.request_state.ensure_database('test2')
        self.delete_db(self.db2._dbname)
        self.db1.close()
        SoledadWithCouchServerMixin.tearDown(self)
        TestWithScenarios.tearDown(self)

    @defer.inlineCallbacks
    def test_sync_exchange_send(self):
        """
        Test for sync exchanging send of document.

        This test was adapted to decrypt remote content before assert.
        """
        db = self.db2
        remote_target = self.getSyncTarget()
        other_docs = []

        def receive_doc(doc, gen, trans_id):
            other_docs.append((doc.doc_id, doc.rev, doc.get_json()))

        doc = self.make_document('doc-here', 'replica:1', '{"value": "here"}')
        new_gen, trans_id = yield remote_target.sync_exchange(
            [(doc, 10, 'T-sid')], 'replica', last_known_generation=0,
            last_known_trans_id=None, insert_doc_cb=receive_doc)
        self.assertEqual(1, new_gen)
        self.assertGetEncryptedDoc(
            db, 'doc-here', 'replica:1', '{"value": "here"}', False)

    @defer.inlineCallbacks
    def test_sync_exchange_send_failure_and_retry_scenario(self):
        """
        Test for sync exchange failure and retry.

        This test was adapted to decrypt remote content before assert.
        """

        def blackhole_getstderr(inst):
            return cStringIO.StringIO()

        db = self.db2
        _put_doc_if_newer = db._put_doc_if_newer
        trigger_ids = ['doc-here2']

        def bomb_put_doc_if_newer(self, doc, save_conflict,
                                  replica_uid=None, replica_gen=None,
                                  replica_trans_id=None, number_of_docs=None,
                                  doc_idx=None, sync_id=None):
            if doc.doc_id in trigger_ids:
                raise l2db.errors.U1DBError
            return _put_doc_if_newer(doc, save_conflict=save_conflict,
                                     replica_uid=replica_uid,
                                     replica_gen=replica_gen,
                                     replica_trans_id=replica_trans_id,
                                     number_of_docs=number_of_docs,
                                     doc_idx=doc_idx, sync_id=sync_id)
        from leap.soledad.common.backend import SoledadBackend
        self.patch(
            SoledadBackend, '_put_doc_if_newer', bomb_put_doc_if_newer)
        remote_target = self.getSyncTarget(
            source_replica_uid='replica')
        other_changes = []

        def receive_doc(doc, gen, trans_id):
            other_changes.append(
                (doc.doc_id, doc.rev, doc.get_json(), gen, trans_id))

        doc1 = self.make_document('doc-here', 'replica:1', '{"value": "here"}')
        doc2 = self.make_document('doc-here2', 'replica:1',
                                  '{"value": "here2"}')

        with self.assertRaises(l2db.errors.U1DBError):
            yield remote_target.sync_exchange(
                [(doc1, 10, 'T-sid'), (doc2, 11, 'T-sud')],
                'replica',
                last_known_generation=0,
                last_known_trans_id=None,
                insert_doc_cb=receive_doc)

        self.assertGetEncryptedDoc(
            db, 'doc-here', 'replica:1', '{"value": "here"}',
            False)
        self.assertEqual(
            (10, 'T-sid'), db._get_replica_gen_and_trans_id('replica'))
        self.assertEqual([], other_changes)
        # retry
        trigger_ids = []
        new_gen, trans_id = yield remote_target.sync_exchange(
            [(doc2, 11, 'T-sud')], 'replica', last_known_generation=0,
            last_known_trans_id=None, insert_doc_cb=receive_doc)
        self.assertGetEncryptedDoc(
            db, 'doc-here2', 'replica:1', '{"value": "here2"}',
            False)
        self.assertEqual(
            (11, 'T-sud'), db._get_replica_gen_and_trans_id('replica'))
        self.assertEqual(2, new_gen)
        self.assertEqual(
            ('doc-here', 'replica:1', '{"value": "here"}', 1),
            other_changes[0][:-1])

    @defer.inlineCallbacks
    def test_sync_exchange_send_ensure_callback(self):
        """
        Test for sync exchange failure and retry.

        This test was adapted to decrypt remote content before assert.
        """
        remote_target = self.getSyncTarget()
        other_docs = []
        replica_uid_box = []

        def receive_doc(doc, gen, trans_id):
            other_docs.append((doc.doc_id, doc.rev, doc.get_json()))

        def ensure_cb(replica_uid):
            replica_uid_box.append(replica_uid)

        doc = self.make_document('doc-here', 'replica:1', '{"value": "here"}')
        new_gen, trans_id = yield remote_target.sync_exchange(
            [(doc, 10, 'T-sid')], 'replica', last_known_generation=0,
            last_known_trans_id=None, insert_doc_cb=receive_doc,
            ensure_callback=ensure_cb)
        self.assertEqual(1, new_gen)
        db = self.db2
        self.assertEqual(1, len(replica_uid_box))
        self.assertEqual(db._replica_uid, replica_uid_box[0])
        self.assertGetEncryptedDoc(
            db, 'doc-here', 'replica:1', '{"value": "here"}', False)

    def test_sync_exchange_in_stream_error(self):
        self.skipTest("bypass this test because our sync_exchange process "
                      "does not return u1db error 503 \"unavailable\" for "
                      "now")

    @defer.inlineCallbacks
    def test_get_sync_info(self):
        db = self.db2
        db._set_replica_gen_and_trans_id('other-id', 1, 'T-transid')
        remote_target = self.getSyncTarget(
            source_replica_uid='other-id')
        sync_info = yield remote_target.get_sync_info('other-id')
        self.assertEqual(
            ('test', 0, '', 1, 'T-transid'),
            sync_info)

    @defer.inlineCallbacks
    def test_record_sync_info(self):
        remote_target = self.getSyncTarget(
            source_replica_uid='other-id')
        yield remote_target.record_sync_info('other-id', 2, 'T-transid')
        self.assertEqual((2, 'T-transid'),
                         self.db2._get_replica_gen_and_trans_id('other-id'))

    @defer.inlineCallbacks
    def test_sync_exchange_receive(self):
        db = self.db2
        doc = db.create_doc_from_json('{"value": "there"}')
        remote_target = self.getSyncTarget()
        other_changes = []

        def receive_doc(doc, gen, trans_id):
            other_changes.append(
                (doc.doc_id, doc.rev, doc.get_json(), gen, trans_id))

        new_gen, trans_id = yield remote_target.sync_exchange(
            [], 'replica', last_known_generation=0, last_known_trans_id=None,
            insert_doc_cb=receive_doc)
        self.assertEqual(1, new_gen)
        self.assertEqual(
            (doc.doc_id, doc.rev, '{"value": "there"}', 1),
            other_changes[0][:-1])


# -----------------------------------------------------------------------------
# The following tests come from `u1db.tests.test_sync`.
# -----------------------------------------------------------------------------

target_scenarios = [
    ('mem,token_soledad',
     {'create_db_and_target': make_local_db_and_token_soledad_target,
      'make_app_with_state': make_soledad_app,
      'make_database_for_test': tests.make_memory_database_for_test,
      'copy_database_for_test': tests.copy_memory_database_for_test,
      'make_document_for_test': tests.make_document_for_test})
]


class SoledadDatabaseSyncTargetTests(
        TestWithScenarios,
        SoledadWithCouchServerMixin,
        tests.DatabaseBaseTests,
        tests.TestCaseWithServer):
    """
    Adaptation of u1db.tests.test_sync.DatabaseSyncTargetTests.
    """

    # TODO: implement _set_trace_hook(_shallow) in SoledadHTTPSyncTarget so
    #       skipped tests can be succesfully executed.

    scenarios = target_scenarios

    whitebox = False

    def setUp(self):
        tests.TestCaseWithServer.setUp(self)
        self.other_changes = []
        SoledadWithCouchServerMixin.setUp(self)
        self.db, self.st = make_local_db_and_soledad_target(self)

    def tearDown(self):
        self.db.close()
        self.st.close()
        tests.TestCaseWithServer.tearDown(self)
        SoledadWithCouchServerMixin.tearDown(self)

    def set_trace_hook(self, callback, shallow=False):
        setter = (self.st._set_trace_hook if not shallow else
                  self.st._set_trace_hook_shallow)
        try:
            setter(callback)
        except NotImplementedError:
            self.skipTest("%s does not implement _set_trace_hook"
                          % (self.st.__class__.__name__,))

    @defer.inlineCallbacks
    def test_sync_exchange(self):
        """
        Test sync exchange.

        This test was adapted to decrypt remote content before assert.
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
        Test sync exchange.

        This test was adapted to decrypt remote content before assert.
        """
        docs_by_gen = [
            (self.make_document(
                'doc-id', 'replica:1', tests.simple_doc), 10, 'T-1'),
            (self.make_document(
                'doc-id2', 'replica:1', tests.nested_doc), 11, 'T-2')]
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
        Test sync exchange.

        This test was adapted to avoid JSON serialization comparison as local
        and remote representations might differ. It looks directly at the
        doc's contents instead.
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
            [c[:-3] + c[-2:-1] for c in self.other_changes])
        self.assertEqual(
            json.loads(tests.simple_doc),
            json.loads(self.other_changes[0][2]))
        self.assertEqual(
            json.loads(tests.nested_doc),
            json.loads(self.other_changes[1][2]))
        if self.whitebox:
            self.assertEqual(
                self.db._last_exchange_log['return'],
                {'last_gen': 2, 'docs':
                 [(doc.doc_id, doc.rev), (doc2.doc_id, doc2.rev)]})

    def receive_doc(self, doc, gen, trans_id):
        self.other_changes.append(
            (doc.doc_id, doc.rev, doc.get_json(), gen, trans_id))

    def test_get_sync_target(self):
        self.assertIsNot(None, self.st)

    @defer.inlineCallbacks
    def test_get_sync_info(self):
        sync_info = yield self.st.get_sync_info('other')
        self.assertEqual(
            ('test', 0, '', 0, ''), sync_info)

    @defer.inlineCallbacks
    def test_create_doc_updates_sync_info(self):
        sync_info = yield self.st.get_sync_info('other')
        self.assertEqual(
            ('test', 0, '', 0, ''), sync_info)
        self.db.create_doc_from_json(tests.simple_doc)
        sync_info = yield self.st.get_sync_info('other')
        self.assertEqual(1, sync_info[1])

    @defer.inlineCallbacks
    def test_record_sync_info(self):
        yield self.st.record_sync_info('replica', 10, 'T-transid')
        sync_info = yield self.st.get_sync_info('replica')
        self.assertEqual(
            ('test', 0, '', 10, 'T-transid'), sync_info)

    @defer.inlineCallbacks
    def test_sync_exchange_deleted(self):
        doc = self.db.create_doc_from_json('{}')
        edit_rev = 'replica:1|' + doc.rev
        docs_by_gen = [
            (self.make_document(doc.doc_id, edit_rev, None), 10, 'T-sid')]
        new_gen, trans_id = yield self.st.sync_exchange(
            docs_by_gen, 'replica', last_known_generation=0,
            last_known_trans_id=None, insert_doc_cb=self.receive_doc)
        self.assertGetDocIncludeDeleted(
            self.db, doc.doc_id, edit_rev, None, False)
        self.assertTransactionLog([doc.doc_id, doc.doc_id], self.db)
        last_trans_id = self.getLastTransId(self.db)
        self.assertEqual(([], 2, last_trans_id),
                         (self.other_changes, new_gen, trans_id))
        sync_info = yield self.st.get_sync_info('replica')
        self.assertEqual(10, sync_info[3])

    @defer.inlineCallbacks
    def test_sync_exchange_refuses_conflicts(self):
        doc = self.db.create_doc_from_json(tests.simple_doc)
        self.assertTransactionLog([doc.doc_id], self.db)
        new_doc = '{"key": "altval"}'
        docs_by_gen = [
            (self.make_document(doc.doc_id, 'replica:1', new_doc), 10,
             'T-sid')]
        new_gen, _ = yield self.st.sync_exchange(
            docs_by_gen, 'replica', last_known_generation=0,
            last_known_trans_id=None, insert_doc_cb=self.receive_doc)
        self.assertTransactionLog([doc.doc_id], self.db)
        self.assertEqual(
            (doc.doc_id, doc.rev, tests.simple_doc, 1),
            self.other_changes[0][:-1])
        self.assertEqual(1, new_gen)
        if self.whitebox:
            self.assertEqual(self.db._last_exchange_log['return'],
                             {'last_gen': 1, 'docs': [(doc.doc_id, doc.rev)]})

    @defer.inlineCallbacks
    def test_sync_exchange_ignores_convergence(self):
        doc = self.db.create_doc_from_json(tests.simple_doc)
        self.assertTransactionLog([doc.doc_id], self.db)
        gen, txid = self.db._get_generation_info()
        docs_by_gen = [
            (self.make_document(doc.doc_id, doc.rev, tests.simple_doc),
             10, 'T-sid')]
        new_gen, _ = yield self.st.sync_exchange(
            docs_by_gen, 'replica', last_known_generation=gen,
            last_known_trans_id=txid, insert_doc_cb=self.receive_doc)
        self.assertTransactionLog([doc.doc_id], self.db)
        self.assertEqual(([], 1), (self.other_changes, new_gen))

    @defer.inlineCallbacks
    def test_sync_exchange_returns_new_docs(self):
        doc = self.db.create_doc_from_json(tests.simple_doc)
        self.assertTransactionLog([doc.doc_id], self.db)
        new_gen, _ = yield self.st.sync_exchange(
            [], 'other-replica', last_known_generation=0,
            last_known_trans_id=None, insert_doc_cb=self.receive_doc)
        self.assertTransactionLog([doc.doc_id], self.db)
        self.assertEqual(
            (doc.doc_id, doc.rev, tests.simple_doc, 1),
            self.other_changes[0][:-1])
        self.assertEqual(1, new_gen)
        if self.whitebox:
            self.assertEqual(self.db._last_exchange_log['return'],
                             {'last_gen': 1, 'docs': [(doc.doc_id, doc.rev)]})

    @defer.inlineCallbacks
    def test_sync_exchange_returns_deleted_docs(self):
        doc = self.db.create_doc_from_json(tests.simple_doc)
        self.db.delete_doc(doc)
        self.assertTransactionLog([doc.doc_id, doc.doc_id], self.db)
        new_gen, _ = yield self.st.sync_exchange(
            [], 'other-replica', last_known_generation=0,
            last_known_trans_id=None, insert_doc_cb=self.receive_doc)
        self.assertTransactionLog([doc.doc_id, doc.doc_id], self.db)
        self.assertEqual(
            (doc.doc_id, doc.rev, None, 2), self.other_changes[0][:-1])
        self.assertEqual(2, new_gen)
        if self.whitebox:
            self.assertEqual(self.db._last_exchange_log['return'],
                             {'last_gen': 2, 'docs': [(doc.doc_id, doc.rev)]})

    @defer.inlineCallbacks
    def test_sync_exchange_getting_newer_docs(self):
        doc = self.db.create_doc_from_json(tests.simple_doc)
        self.assertTransactionLog([doc.doc_id], self.db)
        new_doc = '{"key": "altval"}'
        docs_by_gen = [
            (self.make_document(doc.doc_id, 'test:1|z:2', new_doc), 10,
             'T-sid')]
        new_gen, _ = yield self.st.sync_exchange(
            docs_by_gen, 'other-replica', last_known_generation=0,
            last_known_trans_id=None, insert_doc_cb=self.receive_doc)
        self.assertTransactionLog([doc.doc_id, doc.doc_id], self.db)
        self.assertEqual(([], 2), (self.other_changes, new_gen))

    @defer.inlineCallbacks
    def test_sync_exchange_with_concurrent_updates_of_synced_doc(self):
        expected = []

        def before_whatschanged_cb(state):
            if state != 'before whats_changed':
                return
            cont = '{"key": "cuncurrent"}'
            conc_rev = self.db.put_doc(
                self.make_document(doc.doc_id, 'test:1|z:2', cont))
            expected.append((doc.doc_id, conc_rev, cont, 3))

        self.set_trace_hook(before_whatschanged_cb)
        doc = self.db.create_doc_from_json(tests.simple_doc)
        self.assertTransactionLog([doc.doc_id], self.db)
        new_doc = '{"key": "altval"}'
        docs_by_gen = [
            (self.make_document(doc.doc_id, 'test:1|z:2', new_doc), 10,
             'T-sid')]
        new_gen, _ = yield self.st.sync_exchange(
            docs_by_gen, 'other-replica', last_known_generation=0,
            last_known_trans_id=None, insert_doc_cb=self.receive_doc)
        self.assertEqual(expected, [c[:-1] for c in self.other_changes])
        self.assertEqual(3, new_gen)

    @defer.inlineCallbacks
    def test_sync_exchange_with_concurrent_updates(self):

        def after_whatschanged_cb(state):
            if state != 'after whats_changed':
                return
            self.db.create_doc_from_json('{"new": "doc"}')

        self.set_trace_hook(after_whatschanged_cb)
        doc = self.db.create_doc_from_json(tests.simple_doc)
        self.assertTransactionLog([doc.doc_id], self.db)
        new_doc = '{"key": "altval"}'
        docs_by_gen = [
            (self.make_document(doc.doc_id, 'test:1|z:2', new_doc), 10,
             'T-sid')]
        new_gen, _ = yield self.st.sync_exchange(
            docs_by_gen, 'other-replica', last_known_generation=0,
            last_known_trans_id=None, insert_doc_cb=self.receive_doc)
        self.assertEqual(([], 2), (self.other_changes, new_gen))

    @defer.inlineCallbacks
    def test_sync_exchange_converged_handling(self):
        doc = self.db.create_doc_from_json(tests.simple_doc)
        docs_by_gen = [
            (self.make_document('new', 'other:1', '{}'), 4, 'T-foo'),
            (self.make_document(doc.doc_id, doc.rev, doc.get_json()), 5,
             'T-bar')]
        new_gen, _ = yield self.st.sync_exchange(
            docs_by_gen, 'other-replica', last_known_generation=0,
            last_known_trans_id=None, insert_doc_cb=self.receive_doc)
        self.assertEqual(([], 2), (self.other_changes, new_gen))

    @defer.inlineCallbacks
    def test_sync_exchange_detect_incomplete_exchange(self):
        def before_get_docs_explode(state):
            if state != 'before get_docs':
                return
            raise l2db.errors.U1DBError("fail")
        self.set_trace_hook(before_get_docs_explode)
        # suppress traceback printing in the wsgiref server
        # self.patch(simple_server.ServerHandler,
        #           'log_exception', lambda h, exc_info: None)
        doc = self.db.create_doc_from_json(tests.simple_doc)
        self.assertTransactionLog([doc.doc_id], self.db)
        self.assertRaises(
            (l2db.errors.U1DBError, l2db.errors.BrokenSyncStream),
            self.st.sync_exchange, [], 'other-replica',
            last_known_generation=0, last_known_trans_id=None,
            insert_doc_cb=self.receive_doc)

    @defer.inlineCallbacks
    def test_sync_exchange_doc_ids(self):
        sync_exchange_doc_ids = getattr(self.st, 'sync_exchange_doc_ids', None)
        if sync_exchange_doc_ids is None:
            self.skipTest("sync_exchange_doc_ids not implemented")
        db2 = self.create_database('test2')
        doc = db2.create_doc_from_json(tests.simple_doc)
        new_gen, trans_id = yield sync_exchange_doc_ids(
            db2, [(doc.doc_id, 10, 'T-sid')], 0, None,
            insert_doc_cb=self.receive_doc)
        self.assertGetDoc(self.db, doc.doc_id, doc.rev,
                          tests.simple_doc, False)
        self.assertTransactionLog([doc.doc_id], self.db)
        last_trans_id = self.getLastTransId(self.db)
        self.assertEqual(([], 1, last_trans_id),
                         (self.other_changes, new_gen, trans_id))
        self.assertEqual(10, self.st.get_sync_info(db2._replica_uid)[3])

    @defer.inlineCallbacks
    def test__set_trace_hook(self):
        called = []

        def cb(state):
            called.append(state)

        self.set_trace_hook(cb)
        yield self.st.sync_exchange([], 'replica', 0, None, self.receive_doc)
        yield self.st.record_sync_info('replica', 0, 'T-sid')
        self.assertEqual(['before whats_changed',
                          'after whats_changed',
                          'before get_docs',
                          'record_sync_info',
                          ],
                         called)

    @defer.inlineCallbacks
    def test__set_trace_hook_shallow(self):
        if (self.st._set_trace_hook_shallow == self.st._set_trace_hook or
            self.st._set_trace_hook_shallow.im_func ==
                target.SoledadHTTPSyncTarget._set_trace_hook_shallow.im_func):
            # shallow same as full
            expected = ['before whats_changed',
                        'after whats_changed',
                        'before get_docs',
                        'record_sync_info',
                        ]
        else:
            expected = ['sync_exchange', 'record_sync_info']

        called = []

        def cb(state):
            called.append(state)

        self.set_trace_hook(cb, shallow=True)
        yield self.st.sync_exchange([], 'replica', 0, None, self.receive_doc)
        yield self.st.record_sync_info('replica', 0, 'T-sid')
        self.assertEqual(expected, called)

WAIT_STEP = 1
MAX_WAIT = 10
DBPASS = "pass"


class SyncTimeoutError(Exception):

    """
    Dummy exception to notify timeout during sync.
    """
    pass


class TestSoledadDbSync(
        TestWithScenarios,
        SoledadWithCouchServerMixin,
        tests.TestCaseWithServer):

    """Test db.sync remote sync shortcut"""

    scenarios = [
        ('py-token-http', {
            'create_db_and_target': make_local_db_and_token_soledad_target,
            'make_app_with_state': make_token_soledad_app,
            'make_database_for_test': make_sqlcipher_database_for_test,
            'token': True
        }),
    ]

    oauth = False
    token = False

    def setUp(self):
        """
        Need to explicitely invoke inicialization on all bases.
        """
        SoledadWithCouchServerMixin.setUp(self)
        self.server = self.server_thread = None
        self.startTwistedServer()
        self.syncer = None

        # config info
        self.db1_file = os.path.join(self.tempdir, "db1.u1db")
        os.unlink(self.db1_file)
        self.db_pass = DBPASS
        self.email = ADDRESS

        # get a random prefix for each test, so we do not mess with
        # concurrency during initialization and shutting down of
        # each local db.
        self.rand_prefix = ''.join(
            map(lambda x: random.choice(string.ascii_letters), range(6)))

        # open test dbs: db1 will be the local sqlcipher db (which
        # instantiates a syncdb). We use the self._soledad instance that was
        # already created on some setUp method.
        import binascii
        tohex = binascii.b2a_hex
        key = tohex(self._soledad.secrets.get_local_storage_key())
        sync_db_key = tohex(self._soledad.secrets.get_sync_db_key())
        dbpath = self._soledad._local_db_path

        self.opts = SQLCipherOptions(
            dbpath, key, is_raw_key=True, create=False,
            defer_encryption=True, sync_db_key=sync_db_key)
        self.db1 = SQLCipherDatabase(self.opts)

        self.db2 = self.request_state._create_database(replica_uid='test')

    def tearDown(self):
        """
        Need to explicitely invoke destruction on all bases.
        """
        dbsyncer = getattr(self, 'dbsyncer', None)
        if dbsyncer:
            dbsyncer.close()
        self.db1.close()
        self.db2.close()
        self._soledad.close()

        # XXX should not access "private" attrs
        shutil.rmtree(os.path.dirname(self._soledad._local_db_path))
        SoledadWithCouchServerMixin.tearDown(self)

    def do_sync(self, target_name):
        """
        Perform sync using SoledadSynchronizer, SoledadSyncTarget
        and Token auth.
        """
        if self.token:
            creds = {'token': {
                'uuid': 'user-uuid',
                'token': 'auth-token',
            }}
            target_url = self.getURL(self.db2._dbname)

            # get a u1db syncer
            crypto = self._soledad._crypto
            replica_uid = self.db1._replica_uid
            dbsyncer = SQLCipherU1DBSync(
                self.opts,
                crypto,
                replica_uid,
                None,
                defer_encryption=True)
            self.dbsyncer = dbsyncer
            return dbsyncer.sync(target_url,
                                 creds=creds)
        else:
            return self._do_sync(self, target_name)

    def _do_sync(self, target_name):
        if self.oauth:
            path = '~/' + target_name
            extra = dict(creds={'oauth': {
                'consumer_key': tests.consumer1.key,
                'consumer_secret': tests.consumer1.secret,
                'token_key': tests.token1.key,
                'token_secret': tests.token1.secret,
            }})
        else:
            path = target_name
            extra = {}
        target_url = self.getURL(path)
        return self.db.sync(target_url, **extra)

    def wait_for_sync(self):
        """
        Wait for sync to finish.
        """
        wait = 0
        syncer = self.syncer
        if syncer is not None:
            while syncer.syncing:
                time.sleep(WAIT_STEP)
                wait += WAIT_STEP
                if wait >= MAX_WAIT:
                    raise SyncTimeoutError

    def test_db_sync(self):
        """
        Test sync.

        Adapted to check for encrypted content.
        """
        doc1 = self.db1.create_doc_from_json(tests.simple_doc)
        doc2 = self.db2.create_doc_from_json(tests.nested_doc)
        d = self.do_sync('test')

        def _assert_successful_sync(results):
            import time
            # need to give time to the encryption to proceed
            # TODO should implement a defer list to subscribe to the
            # all-decrypted event
            time.sleep(2)
            local_gen_before_sync = results
            self.wait_for_sync()

            gen, _, changes = self.db1.whats_changed(local_gen_before_sync)
            self.assertEqual(1, len(changes))

            self.assertEqual(doc2.doc_id, changes[0][0])
            self.assertEqual(1, gen - local_gen_before_sync)

            self.assertGetEncryptedDoc(
                self.db2, doc1.doc_id, doc1.rev, tests.simple_doc, False)
            self.assertGetEncryptedDoc(
                self.db1, doc2.doc_id, doc2.rev, tests.nested_doc, False)

        d.addCallback(_assert_successful_sync)
        return d


class SQLCipherSyncTargetTests(SoledadDatabaseSyncTargetTests):

    # TODO: implement _set_trace_hook(_shallow) in SoledadHTTPSyncTarget so
    #       skipped tests can be succesfully executed.

    scenarios = (tests.multiply_scenarios(SQLCIPHER_SCENARIOS,
                                          target_scenarios))

    whitebox = False
