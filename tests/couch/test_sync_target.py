import json

from leap.soledad.common.l2db import SyncTarget
from leap.soledad.common.l2db import errors as u1db_errors

from testscenarios import TestWithScenarios

from test_soledad import u1db_tests as tests
from test_soledad.util import CouchDBTestCase
from test_soledad.util import make_local_db_and_target
from test_soledad.u1db_tests import DatabaseBaseTests

from .common import simple_doc
from .common import nested_doc
from .common import COUCH_SCENARIOS


target_scenarios = [
    ('local', {'create_db_and_target': make_local_db_and_target}), ]


class CouchBackendSyncTargetTests(
        TestWithScenarios,
        DatabaseBaseTests,
        CouchDBTestCase):

    # TODO: implement _set_trace_hook(_shallow) in CouchSyncTarget so
    #       skipped tests can be succesfully executed.

    # whitebox true means self.db is the actual local db object
    # against which the sync is performed
    whitebox = True

    scenarios = (tests.multiply_scenarios(COUCH_SCENARIOS, target_scenarios))

    def set_trace_hook(self, callback, shallow=False):
        setter = (self.st._set_trace_hook if not shallow else
                  self.st._set_trace_hook_shallow)
        try:
            setter(callback)
        except NotImplementedError:
            self.skipTest("%s does not implement _set_trace_hook"
                          % (self.st.__class__.__name__,))

    def setUp(self):
        CouchDBTestCase.setUp(self)
        # other stuff
        self.db, self.st = self.create_db_and_target(self)
        self.other_changes = []

    def tearDown(self):
        self.db.close()
        CouchDBTestCase.tearDown(self)

    def receive_doc(self, doc, gen, trans_id):
        self.other_changes.append(
            (doc.doc_id, doc.rev, doc.get_json(), gen, trans_id))

    def test_sync_exchange_returns_many_new_docs(self):
        # This test was replicated to allow dictionaries to be compared after
        # JSON expansion (because one dictionary may have many different
        # serialized representations).
        doc = self.db.create_doc_from_json(simple_doc)
        doc2 = self.db.create_doc_from_json(nested_doc)
        self.assertTransactionLog([doc.doc_id, doc2.doc_id], self.db)
        new_gen, _ = self.st.sync_exchange(
            [], 'other-replica', last_known_generation=0,
            last_known_trans_id=None, return_doc_cb=self.receive_doc)
        self.assertTransactionLog([doc.doc_id, doc2.doc_id], self.db)
        self.assertEqual(2, new_gen)
        self.assertEqual(
            [(doc.doc_id, doc.rev, json.loads(simple_doc), 1),
             (doc2.doc_id, doc2.rev, json.loads(nested_doc), 2)],
            [c[:-3] + (json.loads(c[-3]), c[-2]) for c in self.other_changes])
        if self.whitebox:
            self.assertEqual(
                self.db._last_exchange_log['return'],
                {'last_gen': 2, 'docs':
                 [(doc.doc_id, doc.rev), (doc2.doc_id, doc2.rev)]})

    def test_get_sync_target(self):
        self.assertIsNot(None, self.st)

    def test_get_sync_info(self):
        self.assertEqual(
            ('test', 0, '', 0, ''), self.st.get_sync_info('other'))

    def test_create_doc_updates_sync_info(self):
        self.assertEqual(
            ('test', 0, '', 0, ''), self.st.get_sync_info('other'))
        self.db.create_doc_from_json(simple_doc)
        self.assertEqual(1, self.st.get_sync_info('other')[1])

    def test_record_sync_info(self):
        self.st.record_sync_info('replica', 10, 'T-transid')
        self.assertEqual(
            ('test', 0, '', 10, 'T-transid'), self.st.get_sync_info('replica'))

    def test_sync_exchange(self):
        docs_by_gen = [
            (self.make_document('doc-id', 'replica:1', simple_doc), 10,
             'T-sid')]
        new_gen, trans_id = self.st.sync_exchange(
            docs_by_gen, 'replica', last_known_generation=0,
            last_known_trans_id=None, return_doc_cb=self.receive_doc)
        self.assertGetDoc(self.db, 'doc-id', 'replica:1', simple_doc, False)
        self.assertTransactionLog(['doc-id'], self.db)
        last_trans_id = self.getLastTransId(self.db)
        self.assertEqual(([], 1, last_trans_id),
                         (self.other_changes, new_gen, last_trans_id))
        self.assertEqual(10, self.st.get_sync_info('replica')[3])

    def test_sync_exchange_deleted(self):
        doc = self.db.create_doc_from_json('{}')
        edit_rev = 'replica:1|' + doc.rev
        docs_by_gen = [
            (self.make_document(doc.doc_id, edit_rev, None), 10, 'T-sid')]
        new_gen, trans_id = self.st.sync_exchange(
            docs_by_gen, 'replica', last_known_generation=0,
            last_known_trans_id=None, return_doc_cb=self.receive_doc)
        self.assertGetDocIncludeDeleted(
            self.db, doc.doc_id, edit_rev, None, False)
        self.assertTransactionLog([doc.doc_id, doc.doc_id], self.db)
        last_trans_id = self.getLastTransId(self.db)
        self.assertEqual(([], 2, last_trans_id),
                         (self.other_changes, new_gen, trans_id))
        self.assertEqual(10, self.st.get_sync_info('replica')[3])

    def test_sync_exchange_push_many(self):
        docs_by_gen = [
            (self.make_document('doc-id', 'replica:1', simple_doc), 10, 'T-1'),
            (self.make_document('doc-id2', 'replica:1', nested_doc), 11,
             'T-2')]
        new_gen, trans_id = self.st.sync_exchange(
            docs_by_gen, 'replica', last_known_generation=0,
            last_known_trans_id=None, return_doc_cb=self.receive_doc)
        self.assertGetDoc(self.db, 'doc-id', 'replica:1', simple_doc, False)
        self.assertGetDoc(self.db, 'doc-id2', 'replica:1', nested_doc, False)
        self.assertTransactionLog(['doc-id', 'doc-id2'], self.db)
        last_trans_id = self.getLastTransId(self.db)
        self.assertEqual(([], 2, last_trans_id),
                         (self.other_changes, new_gen, trans_id))
        self.assertEqual(11, self.st.get_sync_info('replica')[3])

    def test_sync_exchange_refuses_conflicts(self):
        doc = self.db.create_doc_from_json(simple_doc)
        self.assertTransactionLog([doc.doc_id], self.db)
        new_doc = '{"key": "altval"}'
        docs_by_gen = [
            (self.make_document(doc.doc_id, 'replica:1', new_doc), 10,
             'T-sid')]
        new_gen, _ = self.st.sync_exchange(
            docs_by_gen, 'replica', last_known_generation=0,
            last_known_trans_id=None, return_doc_cb=self.receive_doc)
        self.assertTransactionLog([doc.doc_id], self.db)
        self.assertEqual(
            (doc.doc_id, doc.rev, simple_doc, 1), self.other_changes[0][:-1])
        self.assertEqual(1, new_gen)
        if self.whitebox:
            self.assertEqual(self.db._last_exchange_log['return'],
                             {'last_gen': 1, 'docs': [(doc.doc_id, doc.rev)]})

    def test_sync_exchange_ignores_convergence(self):
        doc = self.db.create_doc_from_json(simple_doc)
        self.assertTransactionLog([doc.doc_id], self.db)
        gen, txid = self.db._get_generation_info()
        docs_by_gen = [
            (self.make_document(doc.doc_id, doc.rev, simple_doc), 10, 'T-sid')]
        new_gen, _ = self.st.sync_exchange(
            docs_by_gen, 'replica', last_known_generation=gen,
            last_known_trans_id=txid, return_doc_cb=self.receive_doc)
        self.assertTransactionLog([doc.doc_id], self.db)
        self.assertEqual(([], 1), (self.other_changes, new_gen))

    def test_sync_exchange_returns_new_docs(self):
        doc = self.db.create_doc_from_json(simple_doc)
        self.assertTransactionLog([doc.doc_id], self.db)
        new_gen, _ = self.st.sync_exchange(
            [], 'other-replica', last_known_generation=0,
            last_known_trans_id=None, return_doc_cb=self.receive_doc)
        self.assertTransactionLog([doc.doc_id], self.db)
        self.assertEqual(
            (doc.doc_id, doc.rev, simple_doc, 1), self.other_changes[0][:-1])
        self.assertEqual(1, new_gen)
        if self.whitebox:
            self.assertEqual(self.db._last_exchange_log['return'],
                             {'last_gen': 1, 'docs': [(doc.doc_id, doc.rev)]})

    def test_sync_exchange_returns_deleted_docs(self):
        doc = self.db.create_doc_from_json(simple_doc)
        self.db.delete_doc(doc)
        self.assertTransactionLog([doc.doc_id, doc.doc_id], self.db)
        new_gen, _ = self.st.sync_exchange(
            [], 'other-replica', last_known_generation=0,
            last_known_trans_id=None, return_doc_cb=self.receive_doc)
        self.assertTransactionLog([doc.doc_id, doc.doc_id], self.db)
        self.assertEqual(
            (doc.doc_id, doc.rev, None, 2), self.other_changes[0][:-1])
        self.assertEqual(2, new_gen)
        if self.whitebox:
            self.assertEqual(self.db._last_exchange_log['return'],
                             {'last_gen': 2, 'docs': [(doc.doc_id, doc.rev)]})

    def test_sync_exchange_getting_newer_docs(self):
        doc = self.db.create_doc_from_json(simple_doc)
        self.assertTransactionLog([doc.doc_id], self.db)
        new_doc = '{"key": "altval"}'
        docs_by_gen = [
            (self.make_document(doc.doc_id, 'test:1|z:2', new_doc), 10,
             'T-sid')]
        new_gen, _ = self.st.sync_exchange(
            docs_by_gen, 'other-replica', last_known_generation=0,
            last_known_trans_id=None, return_doc_cb=self.receive_doc)
        self.assertTransactionLog([doc.doc_id, doc.doc_id], self.db)
        self.assertEqual(([], 2), (self.other_changes, new_gen))

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
        doc = self.db.create_doc_from_json(simple_doc)
        self.assertTransactionLog([doc.doc_id], self.db)
        new_doc = '{"key": "altval"}'
        docs_by_gen = [
            (self.make_document(doc.doc_id, 'test:1|z:2', new_doc), 10,
             'T-sid')]
        new_gen, _ = self.st.sync_exchange(
            docs_by_gen, 'other-replica', last_known_generation=0,
            last_known_trans_id=None, return_doc_cb=self.receive_doc)
        self.assertEqual(expected, [c[:-1] for c in self.other_changes])
        self.assertEqual(3, new_gen)

    def test_sync_exchange_with_concurrent_updates(self):

        def after_whatschanged_cb(state):
            if state != 'after whats_changed':
                return
            self.db.create_doc_from_json('{"new": "doc"}')

        self.set_trace_hook(after_whatschanged_cb)
        doc = self.db.create_doc_from_json(simple_doc)
        self.assertTransactionLog([doc.doc_id], self.db)
        new_doc = '{"key": "altval"}'
        docs_by_gen = [
            (self.make_document(doc.doc_id, 'test:1|z:2', new_doc), 10,
             'T-sid')]
        new_gen, _ = self.st.sync_exchange(
            docs_by_gen, 'other-replica', last_known_generation=0,
            last_known_trans_id=None, return_doc_cb=self.receive_doc)
        self.assertEqual(([], 2), (self.other_changes, new_gen))

    def test_sync_exchange_converged_handling(self):
        doc = self.db.create_doc_from_json(simple_doc)
        docs_by_gen = [
            (self.make_document('new', 'other:1', '{}'), 4, 'T-foo'),
            (self.make_document(doc.doc_id, doc.rev, doc.get_json()), 5,
             'T-bar')]
        new_gen, _ = self.st.sync_exchange(
            docs_by_gen, 'other-replica', last_known_generation=0,
            last_known_trans_id=None, return_doc_cb=self.receive_doc)
        self.assertEqual(([], 2), (self.other_changes, new_gen))

    def test_sync_exchange_detect_incomplete_exchange(self):
        def before_get_docs_explode(state):
            if state != 'before get_docs':
                return
            raise u1db_errors.U1DBError("fail")
        self.set_trace_hook(before_get_docs_explode)
        # suppress traceback printing in the wsgiref server
        # self.patch(simple_server.ServerHandler,
        #           'log_exception', lambda h, exc_info: None)
        doc = self.db.create_doc_from_json(simple_doc)
        self.assertTransactionLog([doc.doc_id], self.db)
        self.assertRaises(
            (u1db_errors.U1DBError, u1db_errors.BrokenSyncStream),
            self.st.sync_exchange, [], 'other-replica',
            last_known_generation=0, last_known_trans_id=None,
            return_doc_cb=self.receive_doc)

    def test_sync_exchange_doc_ids(self):
        sync_exchange_doc_ids = getattr(self.st, 'sync_exchange_doc_ids', None)
        if sync_exchange_doc_ids is None:
            self.skipTest("sync_exchange_doc_ids not implemented")
        db2 = self.create_database('test2')
        doc = db2.create_doc_from_json(simple_doc)
        new_gen, trans_id = sync_exchange_doc_ids(
            db2, [(doc.doc_id, 10, 'T-sid')], 0, None,
            return_doc_cb=self.receive_doc)
        self.assertGetDoc(self.db, doc.doc_id, doc.rev, simple_doc, False)
        self.assertTransactionLog([doc.doc_id], self.db)
        last_trans_id = self.getLastTransId(self.db)
        self.assertEqual(([], 1, last_trans_id),
                         (self.other_changes, new_gen, trans_id))
        self.assertEqual(10, self.st.get_sync_info(db2._replica_uid)[3])

    def test__set_trace_hook(self):
        called = []

        def cb(state):
            called.append(state)

        self.set_trace_hook(cb)
        self.st.sync_exchange([], 'replica', 0, None, self.receive_doc)
        self.st.record_sync_info('replica', 0, 'T-sid')
        self.assertEqual(['before whats_changed',
                          'after whats_changed',
                          'before get_docs',
                          'record_sync_info',
                          ],
                         called)

    def test__set_trace_hook_shallow(self):
        st_trace_shallow = self.st._set_trace_hook_shallow
        target_st_trace_shallow = SyncTarget._set_trace_hook_shallow
        same_meth = st_trace_shallow == self.st._set_trace_hook
        same_fun = st_trace_shallow.im_func == target_st_trace_shallow.im_func
        if (same_meth or same_fun):
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
        self.st.sync_exchange([], 'replica', 0, None, self.receive_doc)
        self.st.record_sync_info('replica', 0, 'T-sid')
        self.assertEqual(expected, called)
