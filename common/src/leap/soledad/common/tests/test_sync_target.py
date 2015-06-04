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
import simplejson as json
import u1db
import random
import string
import shutil

from testscenarios import TestWithScenarios
from urlparse import urljoin

from leap.soledad.client import target
from leap.soledad.client import crypto
from leap.soledad.client.sqlcipher import SQLCipherU1DBSync
from leap.soledad.client.sqlcipher import SQLCipherOptions
from leap.soledad.client.sqlcipher import SQLCipherDatabase

from leap.soledad.common import couch
from leap.soledad.common.document import SoledadDocument

from leap.soledad.common.tests import u1db_tests as tests
from leap.soledad.common.tests.util import make_sqlcipher_database_for_test
from leap.soledad.common.tests.util import make_soledad_app
from leap.soledad.common.tests.util import make_token_soledad_app
from leap.soledad.common.tests.util import make_soledad_document_for_test
from leap.soledad.common.tests.util import token_soledad_sync_target
from leap.soledad.common.tests.util import BaseSoledadTest
from leap.soledad.common.tests.util import SoledadWithCouchServerMixin
from leap.soledad.common.tests.util import ADDRESS
from leap.soledad.common.tests.u1db_tests import test_remote_sync_target
from leap.soledad.common.tests.u1db_tests import test_sync


#-----------------------------------------------------------------------------
# The following tests come from `u1db.tests.test_remote_sync_target`.
#-----------------------------------------------------------------------------

class TestSoledadSyncTargetBasics(
        test_remote_sync_target.TestHTTPSyncTargetBasics):
    """
    Some tests had to be copied to this class so we can instantiate our own
    target.
    """

    def test_parse_url(self):
        remote_target = target.SoledadSyncTarget('http://127.0.0.1:12345/')
        self.assertEqual('http', remote_target._url.scheme)
        self.assertEqual('127.0.0.1', remote_target._url.hostname)
        self.assertEqual(12345, remote_target._url.port)
        self.assertEqual('/', remote_target._url.path)


class TestSoledadParsingSyncStream(
        test_remote_sync_target.TestParsingSyncStream,
        BaseSoledadTest):
    """
    Some tests had to be copied to this class so we can instantiate our own
    target.
    """

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
        tgt = target.SoledadSyncTarget(
            "http://foo/foo", crypto=self._soledad._crypto)

        self.assertRaises(u1db.errors.BrokenSyncStream,
                          tgt._parse_sync_stream, "[\r\n{},\r\n]", None)
        self.assertRaises(u1db.errors.BrokenSyncStream,
                          tgt._parse_sync_stream,
                          '[\r\n{},\r\n{"id": "i", "rev": "r", '
                          '"content": %s, "gen": 3, "trans_id": "T-sid"}'
                          ',\r\n]' % json.dumps(enc_json),
                          lambda doc, gen, trans_id: None)

    def test_wrong_start(self):
        tgt = target.SoledadSyncTarget("http://foo/foo")

        self.assertRaises(u1db.errors.BrokenSyncStream,
                          tgt._parse_sync_stream, "{}\r\n]", None)

        self.assertRaises(u1db.errors.BrokenSyncStream,
                          tgt._parse_sync_stream, "\r\n{}\r\n]", None)

        self.assertRaises(u1db.errors.BrokenSyncStream,
                          tgt._parse_sync_stream, "", None)

    def test_wrong_end(self):
        tgt = target.SoledadSyncTarget("http://foo/foo")

        self.assertRaises(u1db.errors.BrokenSyncStream,
                          tgt._parse_sync_stream, "[\r\n{}", None)

        self.assertRaises(u1db.errors.BrokenSyncStream,
                          tgt._parse_sync_stream, "[\r\n", None)

    def test_missing_comma(self):
        tgt = target.SoledadSyncTarget("http://foo/foo")

        self.assertRaises(u1db.errors.BrokenSyncStream,
                          tgt._parse_sync_stream,
                          '[\r\n{}\r\n{"id": "i", "rev": "r", '
                          '"content": "c", "gen": 3}\r\n]', None)

    def test_no_entries(self):
        tgt = target.SoledadSyncTarget("http://foo/foo")

        self.assertRaises(u1db.errors.BrokenSyncStream,
                          tgt._parse_sync_stream, "[\r\n]", None)

    def test_error_in_stream(self):
        tgt = target.SoledadSyncTarget("http://foo/foo")

        self.assertRaises(u1db.errors.Unavailable,
                          tgt._parse_sync_stream,
                          '[\r\n{"new_generation": 0},'
                          '\r\n{"error": "unavailable"}\r\n', None)

        self.assertRaises(u1db.errors.Unavailable,
                          tgt._parse_sync_stream,
                          '[\r\n{"error": "unavailable"}\r\n', None)

        self.assertRaises(u1db.errors.BrokenSyncStream,
                          tgt._parse_sync_stream,
                          '[\r\n{"error": "?"}\r\n', None)


#
# functions for TestRemoteSyncTargets
#

def make_local_db_and_soledad_target(test, path='test'):
    test.startServer()
    db = test.request_state._create_database(os.path.basename(path))
    st = target.SoledadSyncTarget.connect(
        test.getURL(path), crypto=test._soledad._crypto)
    return db, st


def make_local_db_and_token_soledad_target(test):
    db, st = make_local_db_and_soledad_target(test, 'test')
    st.set_token_credentials('user-uuid', 'auth-token')
    return db, st


class TestSoledadSyncTarget(
        TestWithScenarios,
        SoledadWithCouchServerMixin,
        test_remote_sync_target.TestRemoteSyncTargets):

    scenarios = [
        ('token_soledad',
            {'make_app_with_state': make_token_soledad_app,
             'make_document_for_test': make_soledad_document_for_test,
             'create_db_and_target': make_local_db_and_token_soledad_target,
             'make_database_for_test': make_sqlcipher_database_for_test,
             'sync_target': token_soledad_sync_target}),
    ]

    def setUp(self):
        TestWithScenarios.setUp(self)
        SoledadWithCouchServerMixin.setUp(self)
        self.startServer()
        self.db1 = make_sqlcipher_database_for_test(self, 'test1')
        self.db2 = self.request_state._create_database('test2')

    def tearDown(self):
        #db2, _ = self.request_state.ensure_database('test2')
        self.db2.delete_database()
        self.db1.close()
        SoledadWithCouchServerMixin.tearDown(self)
        TestWithScenarios.tearDown(self)

    def test_sync_exchange_send(self):
        """
        Test for sync exchanging send of document.

        This test was adapted to decrypt remote content before assert.
        """
        db = self.request_state._create_database('test')
        remote_target = self.getSyncTarget('test')
        other_docs = []

        def receive_doc(doc, gen, trans_id):
            other_docs.append((doc.doc_id, doc.rev, doc.get_json()))

        doc = self.make_document('doc-here', 'replica:1', '{"value": "here"}')
        new_gen, trans_id = remote_target.sync_exchange(
            [(doc, 10, 'T-sid')], 'replica', last_known_generation=0,
            last_known_trans_id=None, return_doc_cb=receive_doc,
            defer_decryption=False)
        self.assertEqual(1, new_gen)
        self.assertGetEncryptedDoc(
            db, 'doc-here', 'replica:1', '{"value": "here"}', False)

    def test_sync_exchange_send_failure_and_retry_scenario(self):
        """
        Test for sync exchange failure and retry.

        This test was adapted to decrypt remote content before assert.
        """

        def blackhole_getstderr(inst):
            return cStringIO.StringIO()

        self.patch(self.server.RequestHandlerClass, 'get_stderr',
                   blackhole_getstderr)
        db = self.request_state._create_database('test')
        _put_doc_if_newer = db._put_doc_if_newer
        trigger_ids = ['doc-here2']

        def bomb_put_doc_if_newer(self, doc, save_conflict,
                                  replica_uid=None, replica_gen=None,
                                  replica_trans_id=None, number_of_docs=None,
                                  doc_idx=None, sync_id=None):
            if doc.doc_id in trigger_ids:
                raise Exception
            return _put_doc_if_newer(doc, save_conflict=save_conflict,
                                     replica_uid=replica_uid,
                                     replica_gen=replica_gen,
                                     replica_trans_id=replica_trans_id,
                                     number_of_docs=number_of_docs,
                                     doc_idx=doc_idx, sync_id=sync_id)
        from leap.soledad.common.tests.test_couch import IndexedCouchDatabase
        self.patch(
            IndexedCouchDatabase, '_put_doc_if_newer', bomb_put_doc_if_newer)
        remote_target = self.getSyncTarget('test')
        other_changes = []

        def receive_doc(doc, gen, trans_id):
            other_changes.append(
                (doc.doc_id, doc.rev, doc.get_json(), gen, trans_id))

        doc1 = self.make_document('doc-here', 'replica:1', '{"value": "here"}')
        doc2 = self.make_document('doc-here2', 'replica:1',
                                  '{"value": "here2"}')

        self.assertRaises(
            u1db.errors.HTTPError,
            remote_target.sync_exchange,
            [(doc1, 10, 'T-sid'), (doc2, 11, 'T-sud')],
            'replica', last_known_generation=0, last_known_trans_id=None,
            return_doc_cb=receive_doc)
        self.assertGetEncryptedDoc(
            db, 'doc-here', 'replica:1', '{"value": "here"}',
            False)
        self.assertEqual(
            (10, 'T-sid'), db._get_replica_gen_and_trans_id('replica'))
        self.assertEqual([], other_changes)
        # retry
        trigger_ids = []
        new_gen, trans_id = remote_target.sync_exchange(
            [(doc2, 11, 'T-sud')], 'replica', last_known_generation=0,
            last_known_trans_id=None, return_doc_cb=receive_doc)
        self.assertGetEncryptedDoc(
            db, 'doc-here2', 'replica:1', '{"value": "here2"}',
            False)
        self.assertEqual(
            (11, 'T-sud'), db._get_replica_gen_and_trans_id('replica'))
        self.assertEqual(2, new_gen)
        self.assertEqual(
            ('doc-here', 'replica:1', '{"value": "here"}', 1),
            other_changes[0][:-1])

    def test_sync_exchange_send_ensure_callback(self):
        """
        Test for sync exchange failure and retry.

        This test was adapted to decrypt remote content before assert.
        """
        remote_target = self.getSyncTarget('test')
        other_docs = []
        replica_uid_box = []

        def receive_doc(doc, gen, trans_id):
            other_docs.append((doc.doc_id, doc.rev, doc.get_json()))

        def ensure_cb(replica_uid):
            replica_uid_box.append(replica_uid)

        doc = self.make_document('doc-here', 'replica:1', '{"value": "here"}')
        new_gen, trans_id = remote_target.sync_exchange(
            [(doc, 10, 'T-sid')], 'replica', last_known_generation=0,
            last_known_trans_id=None, return_doc_cb=receive_doc,
            ensure_callback=ensure_cb, defer_decryption=False)
        self.assertEqual(1, new_gen)
        db = self.request_state.open_database('test')
        self.assertEqual(1, len(replica_uid_box))
        self.assertEqual(db._replica_uid, replica_uid_box[0])
        self.assertGetEncryptedDoc(
            db, 'doc-here', 'replica:1', '{"value": "here"}', False)

    def test_sync_exchange_in_stream_error(self):
        # we bypass this test because our sync_exchange process does not
        # return u1db error 503 "unavailable" for now.
        pass


#-----------------------------------------------------------------------------
# The following tests come from `u1db.tests.test_sync`.
#-----------------------------------------------------------------------------

target_scenarios = [
    ('token_leap', {'create_db_and_target':
                    make_local_db_and_token_soledad_target,
                    'make_app_with_state': make_soledad_app}),
]


class SoledadDatabaseSyncTargetTests(
        TestWithScenarios,
        SoledadWithCouchServerMixin,
        test_sync.DatabaseSyncTargetTests):

    scenarios = (
        tests.multiply_scenarios(
            tests.DatabaseBaseTests.scenarios,
            target_scenarios))

    whitebox = False

    def setUp(self):
        self.main_test_class = test_sync.DatabaseSyncTargetTests
        SoledadWithCouchServerMixin.setUp(self)

    def test_sync_exchange(self):
        """
        Test sync exchange.

        This test was adapted to decrypt remote content before assert.
        """
        sol, _ = make_local_db_and_soledad_target(self)
        docs_by_gen = [
            (self.make_document('doc-id', 'replica:1', tests.simple_doc), 10,
             'T-sid')]
        new_gen, trans_id = self.st.sync_exchange(
            docs_by_gen, 'replica', last_known_generation=0,
            last_known_trans_id=None, return_doc_cb=self.receive_doc,
            defer_decryption=False)
        self.assertGetEncryptedDoc(
            self.db, 'doc-id', 'replica:1', tests.simple_doc, False)
        self.assertTransactionLog(['doc-id'], self.db)
        last_trans_id = self.getLastTransId(self.db)
        self.assertEqual(([], 1, last_trans_id),
                         (self.other_changes, new_gen, last_trans_id))
        self.assertEqual(10, self.st.get_sync_info('replica')[3])
        sol.close()

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
        new_gen, trans_id = self.st.sync_exchange(
            docs_by_gen, 'replica', last_known_generation=0,
            last_known_trans_id=None, return_doc_cb=self.receive_doc,
            defer_decryption=False)
        self.assertGetEncryptedDoc(
            self.db, 'doc-id', 'replica:1', tests.simple_doc, False)
        self.assertGetEncryptedDoc(
            self.db, 'doc-id2', 'replica:1', tests.nested_doc, False)
        self.assertTransactionLog(['doc-id', 'doc-id2'], self.db)
        last_trans_id = self.getLastTransId(self.db)
        self.assertEqual(([], 2, last_trans_id),
                         (self.other_changes, new_gen, trans_id))
        self.assertEqual(11, self.st.get_sync_info('replica')[3])

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
        new_gen, _ = self.st.sync_exchange(
            [], 'other-replica', last_known_generation=0,
            last_known_trans_id=None, return_doc_cb=self.receive_doc,
            defer_decryption=False)
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


# Just to make clear how this test is different... :)
DEFER_DECRYPTION = False

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
        test_sync.TestDbSync):
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


    def make_app(self):
        self.request_state = couch.CouchServerState(self._couch_url)
        return self.make_app_with_state(self.request_state)

    def setUp(self):
        """
        Need to explicitely invoke inicialization on all bases.
        """
        SoledadWithCouchServerMixin.setUp(self)
        self.server = self.server_thread = None
        self.startServer()
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

        self.db2 = couch.CouchDatabase.open_database(
            urljoin(
                'http://localhost:' + str(self.wrapper.port), 'test'),
                create=True,
                ensure_ddocs=True)

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
            creds={'token': {
                'uuid': 'user-uuid',
                'token': 'auth-token',
            }}
            target_url = self.getURL(target_name)

            # get a u1db syncer
            crypto = self._soledad._crypto
            replica_uid = self.db1._replica_uid
            dbsyncer = SQLCipherU1DBSync(self.opts, crypto, replica_uid,
                defer_encryption=True)
            self.dbsyncer = dbsyncer
            return dbsyncer.sync(target_url, creds=creds,
                autocreate=True,defer_decryption=DEFER_DECRYPTION)
        else:
            return test_sync.TestDbSync.do_sync(self, target_name)

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
            # TODO should implement a defer list to subscribe to the all-decrypted
            # event
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

    def test_db_sync_autocreate(self):
        """
        We bypass this test because we never need to autocreate databases.
        """
        pass
