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
Test sqlcipher backend internals.
"""
import os
import time
import simplejson as json
import threading


from pysqlcipher import dbapi2
from StringIO import StringIO
from urlparse import urljoin


# u1db stuff.
from u1db import (
    errors,
    query_parser,
    sync,
    vectorclock,
)
from u1db.backends.sqlite_backend import SQLitePartialExpandDatabase


# soledad stuff.
from leap.soledad.common.document import SoledadDocument
from leap.soledad.client.sqlcipher import (
    SQLCipherDatabase,
    DatabaseIsNotEncrypted,
    open as u1db_open,
)
from leap.soledad.client.target import SoledadSyncTarget
from leap.soledad.common.crypto import ENC_SCHEME_KEY
from leap.soledad.client.crypto import decrypt_doc_dict


# u1db tests stuff.
from leap.common.testing.basetest import BaseLeapTest
from leap.soledad.common.tests import u1db_tests as tests, BaseSoledadTest
from leap.soledad.common.tests.u1db_tests import test_sqlite_backend
from leap.soledad.common.tests.u1db_tests import test_backends
from leap.soledad.common.tests.u1db_tests import test_open
from leap.soledad.common.tests.u1db_tests import test_sync
from leap.soledad.common.tests.util import (
    make_sqlcipher_database_for_test,
    copy_sqlcipher_database_for_test,
    make_soledad_app,
    SoledadWithCouchServerMixin,
    PASSWORD,
)


#-----------------------------------------------------------------------------
# The following tests come from `u1db.tests.test_common_backend`.
#-----------------------------------------------------------------------------

class TestSQLCipherBackendImpl(tests.TestCase):

    def test__allocate_doc_id(self):
        db = SQLCipherDatabase(':memory:', PASSWORD)
        doc_id1 = db._allocate_doc_id()
        self.assertTrue(doc_id1.startswith('D-'))
        self.assertEqual(34, len(doc_id1))
        int(doc_id1[len('D-'):], 16)
        self.assertNotEqual(doc_id1, db._allocate_doc_id())


#-----------------------------------------------------------------------------
# The following tests come from `u1db.tests.test_backends`.
#-----------------------------------------------------------------------------

def make_document_for_test(test, doc_id, rev, content, has_conflicts=False):
    return SoledadDocument(doc_id, rev, content, has_conflicts=has_conflicts)


SQLCIPHER_SCENARIOS = [
    ('sqlcipher', {'make_database_for_test': make_sqlcipher_database_for_test,
                   'copy_database_for_test': copy_sqlcipher_database_for_test,
                   'make_document_for_test': make_document_for_test, }),
]


class SQLCipherTests(test_backends.AllDatabaseTests):
    scenarios = SQLCIPHER_SCENARIOS


class SQLCipherDatabaseTests(test_backends.LocalDatabaseTests):
    scenarios = SQLCIPHER_SCENARIOS


class SQLCipherValidateGenNTransIdTests(
        test_backends.LocalDatabaseValidateGenNTransIdTests):
    scenarios = SQLCIPHER_SCENARIOS


class SQLCipherValidateSourceGenTests(
        test_backends.LocalDatabaseValidateSourceGenTests):
    scenarios = SQLCIPHER_SCENARIOS


class SQLCipherWithConflictsTests(
        test_backends.LocalDatabaseWithConflictsTests):
    scenarios = SQLCIPHER_SCENARIOS


class SQLCipherIndexTests(test_backends.DatabaseIndexTests):
    scenarios = SQLCIPHER_SCENARIOS


load_tests = tests.load_with_scenarios


#-----------------------------------------------------------------------------
# The following tests come from `u1db.tests.test_sqlite_backend`.
#-----------------------------------------------------------------------------

class TestSQLCipherDatabase(test_sqlite_backend.TestSQLiteDatabase):

    def test_atomic_initialize(self):
        tmpdir = self.createTempDir()
        dbname = os.path.join(tmpdir, 'atomic.db')

        t2 = None  # will be a thread

        class SQLCipherDatabaseTesting(SQLCipherDatabase):
            _index_storage_value = "testing"

            def __init__(self, dbname, ntry):
                self._try = ntry
                self._is_initialized_invocations = 0
                SQLCipherDatabase.__init__(self, dbname, PASSWORD)

            def _is_initialized(self, c):
                res = \
                    SQLCipherDatabase._is_initialized(self, c)
                if self._try == 1:
                    self._is_initialized_invocations += 1
                    if self._is_initialized_invocations == 2:
                        t2.start()
                        # hard to do better and have a generic test
                        time.sleep(0.05)
                return res

        outcome2 = []

        def second_try():
            try:
                db2 = SQLCipherDatabaseTesting(dbname, 2)
            except Exception, e:
                outcome2.append(e)
            else:
                outcome2.append(db2)

        t2 = threading.Thread(target=second_try)
        db1 = SQLCipherDatabaseTesting(dbname, 1)
        t2.join()

        self.assertIsInstance(outcome2[0], SQLCipherDatabaseTesting)
        db2 = outcome2[0]
        self.assertTrue(db2._is_initialized(db1._get_sqlite_handle().cursor()))


class TestAlternativeDocument(SoledadDocument):
    """A (not very) alternative implementation of Document."""


class TestSQLCipherPartialExpandDatabase(
        test_sqlite_backend.TestSQLitePartialExpandDatabase):

    # The following tests had to be cloned from u1db because they all
    # instantiate the backend directly, so we need to change that in order to
    # our backend be instantiated in place.

    def setUp(self):
        test_sqlite_backend.TestSQLitePartialExpandDatabase.setUp(self)
        self.db = SQLCipherDatabase(':memory:', PASSWORD)
        self.db._set_replica_uid('test')

    def test_default_replica_uid(self):
        self.db = SQLCipherDatabase(':memory:', PASSWORD)
        self.assertIsNot(None, self.db._replica_uid)
        self.assertEqual(32, len(self.db._replica_uid))
        int(self.db._replica_uid, 16)

    def test__parse_index(self):
        self.db = SQLCipherDatabase(':memory:', PASSWORD)
        g = self.db._parse_index_definition('fieldname')
        self.assertIsInstance(g, query_parser.ExtractField)
        self.assertEqual(['fieldname'], g.field)

    def test__update_indexes(self):
        self.db = SQLCipherDatabase(':memory:', PASSWORD)
        g = self.db._parse_index_definition('fieldname')
        c = self.db._get_sqlite_handle().cursor()
        self.db._update_indexes('doc-id', {'fieldname': 'val'},
                                [('fieldname', g)], c)
        c.execute('SELECT doc_id, field_name, value FROM document_fields')
        self.assertEqual([('doc-id', 'fieldname', 'val')],
                         c.fetchall())

    def test__set_replica_uid(self):
        # Start from scratch, so that replica_uid isn't set.
        self.db = SQLCipherDatabase(':memory:', PASSWORD)
        self.assertIsNot(None, self.db._real_replica_uid)
        self.assertIsNot(None, self.db._replica_uid)
        self.db._set_replica_uid('foo')
        c = self.db._get_sqlite_handle().cursor()
        c.execute("SELECT value FROM u1db_config WHERE name='replica_uid'")
        self.assertEqual(('foo',), c.fetchone())
        self.assertEqual('foo', self.db._real_replica_uid)
        self.assertEqual('foo', self.db._replica_uid)
        self.db._close_sqlite_handle()
        self.assertEqual('foo', self.db._replica_uid)

    def test__open_database(self):
        temp_dir = self.createTempDir(prefix='u1db-test-')
        path = temp_dir + '/test.sqlite'
        SQLCipherDatabase(path, PASSWORD)
        db2 = SQLCipherDatabase._open_database(path, PASSWORD)
        self.assertIsInstance(db2, SQLCipherDatabase)

    def test__open_database_with_factory(self):
        temp_dir = self.createTempDir(prefix='u1db-test-')
        path = temp_dir + '/test.sqlite'
        SQLCipherDatabase(path, PASSWORD)
        db2 = SQLCipherDatabase._open_database(
            path, PASSWORD,
            document_factory=TestAlternativeDocument)
        doc = db2.create_doc({})
        self.assertTrue(isinstance(doc, SoledadDocument))

    def test__open_database_non_existent(self):
        temp_dir = self.createTempDir(prefix='u1db-test-')
        path = temp_dir + '/non-existent.sqlite'
        self.assertRaises(errors.DatabaseDoesNotExist,
                          SQLCipherDatabase._open_database,
                          path, PASSWORD)

    def test__open_database_during_init(self):
        temp_dir = self.createTempDir(prefix='u1db-test-')
        path = temp_dir + '/initialised.db'
        db = SQLCipherDatabase.__new__(
            SQLCipherDatabase)
        db._db_handle = dbapi2.connect(path)  # db is there but not yet init-ed
        db._syncers = {}
        c = db._db_handle.cursor()
        c.execute('PRAGMA key="%s"' % PASSWORD)
        self.addCleanup(db.close)
        observed = []

        class SQLiteDatabaseTesting(SQLCipherDatabase):
            WAIT_FOR_PARALLEL_INIT_HALF_INTERVAL = 0.1

            @classmethod
            def _which_index_storage(cls, c):
                res = SQLCipherDatabase._which_index_storage(c)
                db._ensure_schema()  # init db
                observed.append(res[0])
                return res

        db2 = SQLiteDatabaseTesting._open_database(path, PASSWORD)
        self.addCleanup(db2.close)
        self.assertIsInstance(db2, SQLCipherDatabase)
        self.assertEqual(
            [None,
             SQLCipherDatabase._index_storage_value],
            observed)

    def test__open_database_invalid(self):
        class SQLiteDatabaseTesting(SQLCipherDatabase):
            WAIT_FOR_PARALLEL_INIT_HALF_INTERVAL = 0.1
        temp_dir = self.createTempDir(prefix='u1db-test-')
        path1 = temp_dir + '/invalid1.db'
        with open(path1, 'wb') as f:
            f.write("")
        self.assertRaises(dbapi2.OperationalError,
                          SQLiteDatabaseTesting._open_database, path1,
                          PASSWORD)
        with open(path1, 'wb') as f:
            f.write("invalid")
        self.assertRaises(dbapi2.DatabaseError,
                          SQLiteDatabaseTesting._open_database, path1,
                          PASSWORD)

    def test_open_database_existing(self):
        temp_dir = self.createTempDir(prefix='u1db-test-')
        path = temp_dir + '/existing.sqlite'
        SQLCipherDatabase(path, PASSWORD)
        db2 = SQLCipherDatabase.open_database(path, PASSWORD, create=False)
        self.assertIsInstance(db2, SQLCipherDatabase)

    def test_open_database_with_factory(self):
        temp_dir = self.createTempDir(prefix='u1db-test-')
        path = temp_dir + '/existing.sqlite'
        SQLCipherDatabase(path, PASSWORD)
        db2 = SQLCipherDatabase.open_database(
            path, PASSWORD, create=False,
            document_factory=TestAlternativeDocument)
        doc = db2.create_doc({})
        self.assertTrue(isinstance(doc, SoledadDocument))

    def test_open_database_create(self):
        temp_dir = self.createTempDir(prefix='u1db-test-')
        path = temp_dir + '/new.sqlite'
        SQLCipherDatabase.open_database(path, PASSWORD, create=True)
        db2 = SQLCipherDatabase.open_database(path, PASSWORD, create=False)
        self.assertIsInstance(db2, SQLCipherDatabase)

    def test_create_database_initializes_schema(self):
        # This test had to be cloned because our implementation of SQLCipher
        # backend is referenced with an index_storage_value that includes the
        # word "encrypted". See u1db's sqlite_backend and our
        # sqlcipher_backend for reference.
        raw_db = self.db._get_sqlite_handle()
        c = raw_db.cursor()
        c.execute("SELECT * FROM u1db_config")
        config = dict([(r[0], r[1]) for r in c.fetchall()])
        self.assertEqual({'sql_schema': '0', 'replica_uid': 'test',
                          'index_storage': 'expand referenced encrypted'},
                         config)

    def test_store_syncable(self):
        doc = self.db.create_doc_from_json(tests.simple_doc)
        # assert that docs are syncable by default
        self.assertEqual(True, doc.syncable)
        # assert that we can store syncable = False
        doc.syncable = False
        self.db.put_doc(doc)
        self.assertEqual(False, self.db.get_doc(doc.doc_id).syncable)
        # assert that we can store syncable = True
        doc.syncable = True
        self.db.put_doc(doc)
        self.assertEqual(True, self.db.get_doc(doc.doc_id).syncable)


#-----------------------------------------------------------------------------
# The following tests come from `u1db.tests.test_open`.
#-----------------------------------------------------------------------------

class SQLCipherOpen(test_open.TestU1DBOpen):

    def test_open_no_create(self):
        self.assertRaises(errors.DatabaseDoesNotExist,
                          u1db_open, self.db_path,
                          password=PASSWORD,
                          create=False)
        self.assertFalse(os.path.exists(self.db_path))

    def test_open_create(self):
        db = u1db_open(self.db_path, password=PASSWORD, create=True)
        self.addCleanup(db.close)
        self.assertTrue(os.path.exists(self.db_path))
        self.assertIsInstance(db, SQLCipherDatabase)

    def test_open_with_factory(self):
        db = u1db_open(self.db_path, password=PASSWORD, create=True,
                       document_factory=TestAlternativeDocument)
        self.addCleanup(db.close)
        doc = db.create_doc({})
        self.assertTrue(isinstance(doc, SoledadDocument))

    def test_open_existing(self):
        db = SQLCipherDatabase(self.db_path, PASSWORD)
        self.addCleanup(db.close)
        doc = db.create_doc_from_json(tests.simple_doc)
        # Even though create=True, we shouldn't wipe the db
        db2 = u1db_open(self.db_path, password=PASSWORD, create=True)
        self.addCleanup(db2.close)
        doc2 = db2.get_doc(doc.doc_id)
        self.assertEqual(doc, doc2)

    def test_open_existing_no_create(self):
        db = SQLCipherDatabase(self.db_path, PASSWORD)
        self.addCleanup(db.close)
        db2 = u1db_open(self.db_path, password=PASSWORD, create=False)
        self.addCleanup(db2.close)
        self.assertIsInstance(db2, SQLCipherDatabase)


#-----------------------------------------------------------------------------
# The following tests come from `u1db.tests.test_sync`.
#-----------------------------------------------------------------------------

sync_scenarios = []
for name, scenario in SQLCIPHER_SCENARIOS:
    scenario = dict(scenario)
    scenario['do_sync'] = test_sync.sync_via_synchronizer
    sync_scenarios.append((name, scenario))
    scenario = dict(scenario)


def sync_via_synchronizer_and_leap(test, db_source, db_target,
                                   trace_hook=None, trace_hook_shallow=None):
    if trace_hook:
        test.skipTest("full trace hook unsupported over http")
    path = test._http_at[db_target]
    target = SoledadSyncTarget.connect(
        test.getURL(path), test._soledad._crypto)
    target.set_token_credentials('user-uuid', 'auth-token')
    if trace_hook_shallow:
        target._set_trace_hook_shallow(trace_hook_shallow)
    return sync.Synchronizer(db_source, target).sync()


sync_scenarios.append(('pyleap', {
    'make_database_for_test': test_sync.make_database_for_http_test,
    'copy_database_for_test': test_sync.copy_database_for_http_test,
    'make_document_for_test': make_document_for_test,
    'make_app_with_state': tests.test_remote_sync_target.make_http_app,
    'do_sync': test_sync.sync_via_synchronizer,
}))


class SQLCipherDatabaseSyncTests(
        test_sync.DatabaseSyncTests, BaseSoledadTest):
    """
    Test for succesfull sync between SQLCipher and LeapBackend.

    Some of the tests in this class had to be adapted because the remote
    backend always receive encrypted content, and so it can not rely on
    document's content comparison to try to autoresolve conflicts.
    """

    scenarios = sync_scenarios

    def setUp(self):
        test_sync.DatabaseSyncTests.setUp(self)

    def tearDown(self):
        test_sync.DatabaseSyncTests.tearDown(self)

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
        #self.assertEqual(doc.rev, self.db2.get_doc('doc').rev)
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
    test.startServer()
    db = test.request_state._create_database(os.path.basename(path))
    st = SoledadSyncTarget.connect(
        test.getURL(path), crypto=test._soledad._crypto)
    st.set_token_credentials('user-uuid', 'auth-token')
    return db, st


target_scenarios = [
    ('leap', {
        'create_db_and_target': _make_local_db_and_token_http_target,
#        'make_app_with_state': tests.test_remote_sync_target.make_http_app,
        'make_app_with_state': make_soledad_app,
        'do_sync': test_sync.sync_via_synchronizer}),
]


class SQLCipherSyncTargetTests(
        SoledadWithCouchServerMixin, test_sync.DatabaseSyncTargetTests):

    scenarios = (tests.multiply_scenarios(SQLCIPHER_SCENARIOS,
                                          target_scenarios))

    whitebox = False

    def setUp(self):
        self.main_test_class = test_sync.DatabaseSyncTargetTests
        SoledadWithCouchServerMixin.setUp(self)

    def test_sync_exchange(self):
        """
        Modified to account for possibly receiving encrypted documents from
        sever-side.
        """
        docs_by_gen = [
            (self.make_document('doc-id', 'replica:1', tests.simple_doc), 10,
             'T-sid')]
        new_gen, trans_id = self.st.sync_exchange(
            docs_by_gen, 'replica', last_known_generation=0,
            last_known_trans_id=None, return_doc_cb=self.receive_doc)
        self.assertGetEncryptedDoc(
            self.db, 'doc-id', 'replica:1', tests.simple_doc, False)
        self.assertTransactionLog(['doc-id'], self.db)
        last_trans_id = self.getLastTransId(self.db)
        self.assertEqual(([], 1, last_trans_id),
                         (self.other_changes, new_gen, last_trans_id))
        self.assertEqual(10, self.st.get_sync_info('replica')[3])

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
        new_gen, trans_id = self.st.sync_exchange(
            docs_by_gen, 'replica', last_known_generation=0,
            last_known_trans_id=None, return_doc_cb=self.receive_doc)
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
        Modified to account for JSON serialization differences.
        """
        doc = self.db.create_doc_from_json(tests.simple_doc)
        doc2 = self.db.create_doc_from_json(tests.nested_doc)
        self.assertTransactionLog([doc.doc_id, doc2.doc_id], self.db)
        new_gen, _ = self.st.sync_exchange(
            [], 'other-replica', last_known_generation=0,
            last_known_trans_id=None, return_doc_cb=self.receive_doc)
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


#-----------------------------------------------------------------------------
# Tests for actual encryption of the database
#-----------------------------------------------------------------------------

class SQLCipherEncryptionTest(BaseLeapTest):
    """
    Tests to guarantee SQLCipher is indeed encrypting data when storing.
    """

    def _delete_dbfiles(self):
        for dbfile in [self.DB_FILE]:
            if os.path.exists(dbfile):
                os.unlink(dbfile)

    def setUp(self):
        self.DB_FILE = os.path.join(self.tempdir, 'test.db')
        self._delete_dbfiles()

    def tearDown(self):
        self._delete_dbfiles()

    def test_try_to_open_encrypted_db_with_sqlite_backend(self):
        """
        SQLite backend should not succeed to open SQLCipher databases.
        """
        db = SQLCipherDatabase(self.DB_FILE, PASSWORD)
        doc = db.create_doc_from_json(tests.simple_doc)
        db.close()
        try:
            # trying to open an encrypted database with the regular u1db
            # backend should raise a DatabaseError exception.
            SQLitePartialExpandDatabase(self.DB_FILE,
                                        document_factory=SoledadDocument)
            raise DatabaseIsNotEncrypted()
        except dbapi2.DatabaseError:
            # at this point we know that the regular U1DB sqlcipher backend
            # did not succeed on opening the database, so it was indeed
            # encrypted.
            db = SQLCipherDatabase(self.DB_FILE, PASSWORD)
            doc = db.get_doc(doc.doc_id)
            self.assertEqual(tests.simple_doc, doc.get_json(),
                             'decrypted content mismatch')

    def test_try_to_open_raw_db_with_sqlcipher_backend(self):
        """
        SQLCipher backend should not succeed to open unencrypted databases.
        """
        db = SQLitePartialExpandDatabase(self.DB_FILE,
                                         document_factory=SoledadDocument)
        db.create_doc_from_json(tests.simple_doc)
        db.close()
        try:
            # trying to open the a non-encrypted database with sqlcipher
            # backend should raise a DatabaseIsNotEncrypted exception.
            SQLCipherDatabase(self.DB_FILE, PASSWORD)
            raise dbapi2.DatabaseError(
                "SQLCipher backend should not be able to open non-encrypted "
                "dbs.")
        except DatabaseIsNotEncrypted:
            pass


load_tests = tests.load_with_scenarios
