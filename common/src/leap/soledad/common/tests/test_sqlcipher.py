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
import threading
import tempfile
import shutil

from pysqlcipher import dbapi2
from testscenarios import TestWithScenarios

# u1db stuff.
from u1db import errors
from u1db import query_parser
from u1db.backends.sqlite_backend import SQLitePartialExpandDatabase

# soledad stuff.
from leap.soledad.common import soledad_assert
from leap.soledad.common.document import SoledadDocument
from leap.soledad.client.sqlcipher import SQLCipherDatabase
from leap.soledad.client.sqlcipher import SQLCipherOptions
from leap.soledad.client.sqlcipher import DatabaseIsNotEncrypted

# u1db tests stuff.
from leap.soledad.common.tests import u1db_tests as tests
from leap.soledad.common.tests.u1db_tests import test_backends
from leap.soledad.common.tests.u1db_tests import test_open
from leap.soledad.common.tests.util import make_sqlcipher_database_for_test
from leap.soledad.common.tests.util import copy_sqlcipher_database_for_test
from leap.soledad.common.tests.util import PASSWORD
from leap.soledad.common.tests.util import BaseSoledadTest


def sqlcipher_open(path, passphrase, create=True, document_factory=None):
    return SQLCipherDatabase(
        SQLCipherOptions(path, passphrase, create=create))


# -----------------------------------------------------------------------------
# The following tests come from `u1db.tests.test_common_backend`.
# -----------------------------------------------------------------------------

class TestSQLCipherBackendImpl(tests.TestCase):

    def test__allocate_doc_id(self):
        db = sqlcipher_open(':memory:', PASSWORD)
        doc_id1 = db._allocate_doc_id()
        self.assertTrue(doc_id1.startswith('D-'))
        self.assertEqual(34, len(doc_id1))
        int(doc_id1[len('D-'):], 16)
        self.assertNotEqual(doc_id1, db._allocate_doc_id())
        db.close()


# -----------------------------------------------------------------------------
# The following tests come from `u1db.tests.test_backends`.
# -----------------------------------------------------------------------------

def make_document_for_test(test, doc_id, rev, content, has_conflicts=False):
    return SoledadDocument(doc_id, rev, content, has_conflicts=has_conflicts)


SQLCIPHER_SCENARIOS = [
    ('sqlcipher', {'make_database_for_test': make_sqlcipher_database_for_test,
                   'copy_database_for_test': copy_sqlcipher_database_for_test,
                   'make_document_for_test': make_document_for_test, }),
]


class SQLCipherTests(TestWithScenarios, test_backends.AllDatabaseTests):
    scenarios = SQLCIPHER_SCENARIOS


class SQLCipherDatabaseTests(TestWithScenarios,
                             test_backends.LocalDatabaseTests):
    scenarios = SQLCIPHER_SCENARIOS


class SQLCipherValidateGenNTransIdTests(
        TestWithScenarios,
        test_backends.LocalDatabaseValidateGenNTransIdTests):
    scenarios = SQLCIPHER_SCENARIOS


class SQLCipherValidateSourceGenTests(
        TestWithScenarios,
        test_backends.LocalDatabaseValidateSourceGenTests):
    scenarios = SQLCIPHER_SCENARIOS


class SQLCipherWithConflictsTests(
        TestWithScenarios,
        test_backends.LocalDatabaseWithConflictsTests):
    scenarios = SQLCIPHER_SCENARIOS


class SQLCipherIndexTests(
        TestWithScenarios, test_backends.DatabaseIndexTests):
    scenarios = SQLCIPHER_SCENARIOS


# -----------------------------------------------------------------------------
# The following tests come from `u1db.tests.test_sqlite_backend`.
# -----------------------------------------------------------------------------

class TestSQLCipherDatabase(tests.TestCase):
    """
    Tests from u1db.tests.test_sqlite_backend.TestSQLiteDatabase.
    """

    def test_atomic_initialize(self):
        # This test was modified to ensure that db2.close() is called within
        # the thread that created the database.
        tmpdir = self.createTempDir()
        dbname = os.path.join(tmpdir, 'atomic.db')

        t2 = None  # will be a thread

        class SQLCipherDatabaseTesting(SQLCipherDatabase):
            _index_storage_value = "testing"

            def __init__(self, dbname, ntry):
                self._try = ntry
                self._is_initialized_invocations = 0
                SQLCipherDatabase.__init__(
                    self,
                    SQLCipherOptions(dbname, PASSWORD))

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

        class SecondTry(threading.Thread):

            outcome2 = []

            def run(self):
                try:
                    db2 = SQLCipherDatabaseTesting(dbname, 2)
                except Exception, e:
                    SecondTry.outcome2.append(e)
                else:
                    SecondTry.outcome2.append(db2)

        t2 = SecondTry()
        db1 = SQLCipherDatabaseTesting(dbname, 1)
        t2.join()

        self.assertIsInstance(SecondTry.outcome2[0], SQLCipherDatabaseTesting)
        self.assertTrue(db1._is_initialized(db1._get_sqlite_handle().cursor()))
        db1.close()


class TestAlternativeDocument(SoledadDocument):

    """A (not very) alternative implementation of Document."""


class TestSQLCipherPartialExpandDatabase(tests.TestCase):
    """
    Tests from u1db.tests.test_sqlite_backend.TestSQLitePartialExpandDatabase.
    """

    # The following tests had to be cloned from u1db because they all
    # instantiate the backend directly, so we need to change that in order to
    # our backend be instantiated in place.

    def setUp(self):
        self.db = sqlcipher_open(':memory:', PASSWORD)

    def tearDown(self):
        self.db.close()

    def test_default_replica_uid(self):
        self.assertIsNot(None, self.db._replica_uid)
        self.assertEqual(32, len(self.db._replica_uid))
        int(self.db._replica_uid, 16)

    def test__parse_index(self):
        g = self.db._parse_index_definition('fieldname')
        self.assertIsInstance(g, query_parser.ExtractField)
        self.assertEqual(['fieldname'], g.field)

    def test__update_indexes(self):
        g = self.db._parse_index_definition('fieldname')
        c = self.db._get_sqlite_handle().cursor()
        self.db._update_indexes('doc-id', {'fieldname': 'val'},
                                [('fieldname', g)], c)
        c.execute('SELECT doc_id, field_name, value FROM document_fields')
        self.assertEqual([('doc-id', 'fieldname', 'val')],
                         c.fetchall())

    def test_create_database(self):
        raw_db = self.db._get_sqlite_handle()
        self.assertNotEqual(None, raw_db)

    def test__set_replica_uid(self):
        # Start from scratch, so that replica_uid isn't set.
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
        # SQLCipherDatabase has no _open_database() method, so we just pass
        # (and test for the same funcionality on test_open_database_existing()
        # below).
        pass

    def test__open_database_with_factory(self):
        # SQLCipherDatabase has no _open_database() method.
        pass

    def test__open_database_non_existent(self):
        temp_dir = self.createTempDir(prefix='u1db-test-')
        path = temp_dir + '/non-existent.sqlite'
        self.assertRaises(errors.DatabaseDoesNotExist,
                          sqlcipher_open,
                          path, PASSWORD, create=False)

    def test__open_database_during_init(self):
        # The purpose of this test is to ensure that _open_database() parallel
        # db initialization behaviour is correct. As SQLCipherDatabase does
        # not have an _open_database() method, we just do not implement this
        # test.
        pass

    def test__open_database_invalid(self):
        # This test was modified to ensure that an empty database file will
        # raise a DatabaseIsNotEncrypted exception instead of a
        # dbapi2.OperationalError exception.
        temp_dir = self.createTempDir(prefix='u1db-test-')
        path1 = temp_dir + '/invalid1.db'
        with open(path1, 'wb') as f:
            f.write("")
        self.assertRaises(DatabaseIsNotEncrypted,
                          sqlcipher_open, path1,
                          PASSWORD)
        with open(path1, 'wb') as f:
            f.write("invalid")
        self.assertRaises(dbapi2.DatabaseError,
                          sqlcipher_open, path1,
                          PASSWORD)

    def test_open_database_existing(self):
        # In the context of SQLCipherDatabase, where no _open_database()
        # method exists and thus there's no call to _which_index_storage(),
        # this test tests for the same functionality as
        # test_open_database_create() below. So, we just pass.
        pass

    def test_open_database_with_factory(self):
        # SQLCipherDatabase's constructor has no factory parameter.
        pass

    def test_open_database_create(self):
        # SQLCipherDatabas has no open_database() method, so we just test for
        # the actual database constructor effects.
        temp_dir = self.createTempDir(prefix='u1db-test-')
        path = temp_dir + '/new.sqlite'
        db1 = sqlcipher_open(path, PASSWORD, create=True)
        db2 = sqlcipher_open(path, PASSWORD, create=False)
        self.assertIsInstance(db2, SQLCipherDatabase)
        db1.close()
        db2.close()

    def test_create_database_initializes_schema(self):
        # This test had to be cloned because our implementation of SQLCipher
        # backend is referenced with an index_storage_value that includes the
        # word "encrypted". See u1db's sqlite_backend and our
        # sqlcipher_backend for reference.
        raw_db = self.db._get_sqlite_handle()
        c = raw_db.cursor()
        c.execute("SELECT * FROM u1db_config")
        config = dict([(r[0], r[1]) for r in c.fetchall()])
        replica_uid = self.db._replica_uid
        self.assertEqual({'sql_schema': '0', 'replica_uid': replica_uid,
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

    def test__close_sqlite_handle(self):
        raw_db = self.db._get_sqlite_handle()
        self.db._close_sqlite_handle()
        self.assertRaises(dbapi2.ProgrammingError,
                          raw_db.cursor)

    def test__get_generation(self):
        self.assertEqual(0, self.db._get_generation())

    def test__get_generation_info(self):
        self.assertEqual((0, ''), self.db._get_generation_info())

    def test_create_index(self):
        self.db.create_index('test-idx', "key")
        self.assertEqual([('test-idx', ["key"])], self.db.list_indexes())

    def test_create_index_multiple_fields(self):
        self.db.create_index('test-idx', "key", "key2")
        self.assertEqual([('test-idx', ["key", "key2"])],
                         self.db.list_indexes())

    def test__get_index_definition(self):
        self.db.create_index('test-idx', "key", "key2")
        # TODO: How would you test that an index is getting used for an SQL
        #       request?
        self.assertEqual(["key", "key2"],
                         self.db._get_index_definition('test-idx'))

    def test_list_index_mixed(self):
        # Make sure that we properly order the output
        c = self.db._get_sqlite_handle().cursor()
        # We intentionally insert the data in weird ordering, to make sure the
        # query still gets it back correctly.
        c.executemany("INSERT INTO index_definitions VALUES (?, ?, ?)",
                      [('idx-1', 0, 'key10'),
                       ('idx-2', 2, 'key22'),
                       ('idx-1', 1, 'key11'),
                       ('idx-2', 0, 'key20'),
                       ('idx-2', 1, 'key21')])
        self.assertEqual([('idx-1', ['key10', 'key11']),
                          ('idx-2', ['key20', 'key21', 'key22'])],
                         self.db.list_indexes())

    def test_no_indexes_no_document_fields(self):
        self.db.create_doc_from_json(
            '{"key1": "val1", "key2": "val2"}')
        c = self.db._get_sqlite_handle().cursor()
        c.execute("SELECT doc_id, field_name, value FROM document_fields"
                  " ORDER BY doc_id, field_name, value")
        self.assertEqual([], c.fetchall())

    def test_create_extracts_fields(self):
        doc1 = self.db.create_doc_from_json('{"key1": "val1", "key2": "val2"}')
        doc2 = self.db.create_doc_from_json('{"key1": "valx", "key2": "valy"}')
        c = self.db._get_sqlite_handle().cursor()
        c.execute("SELECT doc_id, field_name, value FROM document_fields"
                  " ORDER BY doc_id, field_name, value")
        self.assertEqual([], c.fetchall())
        self.db.create_index('test', 'key1', 'key2')
        c.execute("SELECT doc_id, field_name, value FROM document_fields"
                  " ORDER BY doc_id, field_name, value")
        self.assertEqual(sorted(
            [(doc1.doc_id, "key1", "val1"),
             (doc1.doc_id, "key2", "val2"),
             (doc2.doc_id, "key1", "valx"),
             (doc2.doc_id, "key2", "valy"), ]), sorted(c.fetchall()))

    def test_put_updates_fields(self):
        self.db.create_index('test', 'key1', 'key2')
        doc1 = self.db.create_doc_from_json(
            '{"key1": "val1", "key2": "val2"}')
        doc1.content = {"key1": "val1", "key2": "valy"}
        self.db.put_doc(doc1)
        c = self.db._get_sqlite_handle().cursor()
        c.execute("SELECT doc_id, field_name, value FROM document_fields"
                  " ORDER BY doc_id, field_name, value")
        self.assertEqual([(doc1.doc_id, "key1", "val1"),
                          (doc1.doc_id, "key2", "valy"), ], c.fetchall())

    def test_put_updates_nested_fields(self):
        self.db.create_index('test', 'key', 'sub.doc')
        doc1 = self.db.create_doc_from_json(tests.nested_doc)
        c = self.db._get_sqlite_handle().cursor()
        c.execute("SELECT doc_id, field_name, value FROM document_fields"
                  " ORDER BY doc_id, field_name, value")
        self.assertEqual([(doc1.doc_id, "key", "value"),
                          (doc1.doc_id, "sub.doc", "underneath"), ],
                         c.fetchall())

    def test__ensure_schema_rollback(self):
        temp_dir = self.createTempDir(prefix='u1db-test-')
        path = temp_dir + '/rollback.db'

        class SQLitePartialExpandDbTesting(SQLCipherDatabase):

            def _set_replica_uid_in_transaction(self, uid):
                super(SQLitePartialExpandDbTesting,
                      self)._set_replica_uid_in_transaction(uid)
                if fail:
                    raise Exception()

        db = SQLitePartialExpandDbTesting.__new__(SQLitePartialExpandDbTesting)
        db._db_handle = dbapi2.connect(path)  # db is there but not yet init-ed
        fail = True
        self.assertRaises(Exception, db._ensure_schema)
        fail = False
        db._initialize(db._db_handle.cursor())

    def test_open_database_non_existent(self):
        temp_dir = self.createTempDir(prefix='u1db-test-')
        path = temp_dir + '/non-existent.sqlite'
        self.assertRaises(errors.DatabaseDoesNotExist,
                          sqlcipher_open, path, "123",
                          create=False)

    def test_delete_database_existent(self):
        temp_dir = self.createTempDir(prefix='u1db-test-')
        path = temp_dir + '/new.sqlite'
        db = sqlcipher_open(path, "123", create=True)
        db.close()
        SQLCipherDatabase.delete_database(path)
        self.assertRaises(errors.DatabaseDoesNotExist,
                          sqlcipher_open, path, "123",
                          create=False)

    def test_delete_database_nonexistent(self):
        temp_dir = self.createTempDir(prefix='u1db-test-')
        path = temp_dir + '/non-existent.sqlite'
        self.assertRaises(errors.DatabaseDoesNotExist,
                          SQLCipherDatabase.delete_database, path)

    def test__get_indexed_fields(self):
        self.db.create_index('idx1', 'a', 'b')
        self.assertEqual(set(['a', 'b']), self.db._get_indexed_fields())
        self.db.create_index('idx2', 'b', 'c')
        self.assertEqual(set(['a', 'b', 'c']), self.db._get_indexed_fields())

    def test_indexed_fields_expanded(self):
        self.db.create_index('idx1', 'key1')
        doc1 = self.db.create_doc_from_json('{"key1": "val1", "key2": "val2"}')
        self.assertEqual(set(['key1']), self.db._get_indexed_fields())
        c = self.db._get_sqlite_handle().cursor()
        c.execute("SELECT doc_id, field_name, value FROM document_fields"
                  " ORDER BY doc_id, field_name, value")
        self.assertEqual([(doc1.doc_id, 'key1', 'val1')], c.fetchall())

    def test_create_index_updates_fields(self):
        doc1 = self.db.create_doc_from_json('{"key1": "val1", "key2": "val2"}')
        self.db.create_index('idx1', 'key1')
        self.assertEqual(set(['key1']), self.db._get_indexed_fields())
        c = self.db._get_sqlite_handle().cursor()
        c.execute("SELECT doc_id, field_name, value FROM document_fields"
                  " ORDER BY doc_id, field_name, value")
        self.assertEqual([(doc1.doc_id, 'key1', 'val1')], c.fetchall())

    def assertFormatQueryEquals(self, exp_statement, exp_args, definition,
                                values):
        statement, args = self.db._format_query(definition, values)
        self.assertEqual(exp_statement, statement)
        self.assertEqual(exp_args, args)

    def test__format_query(self):
        self.assertFormatQueryEquals(
            "SELECT d.doc_id, d.doc_rev, d.content, count(c.doc_rev) FROM "
            "document d, document_fields d0 LEFT OUTER JOIN conflicts c ON "
            "c.doc_id = d.doc_id WHERE d.doc_id = d0.doc_id AND d0.field_name "
            "= ? AND d0.value = ? GROUP BY d.doc_id, d.doc_rev, d.content "
            "ORDER BY d0.value;", ["key1", "a"],
            ["key1"], ["a"])

    def test__format_query2(self):
        self.assertFormatQueryEquals(
            'SELECT d.doc_id, d.doc_rev, d.content, count(c.doc_rev) FROM '
            'document d, document_fields d0, document_fields d1, '
            'document_fields d2 LEFT OUTER JOIN conflicts c ON c.doc_id = '
            'd.doc_id WHERE d.doc_id = d0.doc_id AND d0.field_name = ? AND '
            'd0.value = ? AND d.doc_id = d1.doc_id AND d1.field_name = ? AND '
            'd1.value = ? AND d.doc_id = d2.doc_id AND d2.field_name = ? AND '
            'd2.value = ? GROUP BY d.doc_id, d.doc_rev, d.content ORDER BY '
            'd0.value, d1.value, d2.value;',
            ["key1", "a", "key2", "b", "key3", "c"],
            ["key1", "key2", "key3"], ["a", "b", "c"])

    def test__format_query_wildcard(self):
        self.assertFormatQueryEquals(
            'SELECT d.doc_id, d.doc_rev, d.content, count(c.doc_rev) FROM '
            'document d, document_fields d0, document_fields d1, '
            'document_fields d2 LEFT OUTER JOIN conflicts c ON c.doc_id = '
            'd.doc_id WHERE d.doc_id = d0.doc_id AND d0.field_name = ? AND '
            'd0.value = ? AND d.doc_id = d1.doc_id AND d1.field_name = ? AND '
            'd1.value GLOB ? AND d.doc_id = d2.doc_id AND d2.field_name = ? '
            'AND d2.value NOT NULL GROUP BY d.doc_id, d.doc_rev, d.content '
            'ORDER BY d0.value, d1.value, d2.value;',
            ["key1", "a", "key2", "b*", "key3"], ["key1", "key2", "key3"],
            ["a", "b*", "*"])

    def assertFormatRangeQueryEquals(self, exp_statement, exp_args, definition,
                                     start_value, end_value):
        statement, args = self.db._format_range_query(
            definition, start_value, end_value)
        self.assertEqual(exp_statement, statement)
        self.assertEqual(exp_args, args)

    def test__format_range_query(self):
        self.assertFormatRangeQueryEquals(
            'SELECT d.doc_id, d.doc_rev, d.content, count(c.doc_rev) FROM '
            'document d, document_fields d0, document_fields d1, '
            'document_fields d2 LEFT OUTER JOIN conflicts c ON c.doc_id = '
            'd.doc_id WHERE d.doc_id = d0.doc_id AND d0.field_name = ? AND '
            'd0.value >= ? AND d.doc_id = d1.doc_id AND d1.field_name = ? AND '
            'd1.value >= ? AND d.doc_id = d2.doc_id AND d2.field_name = ? AND '
            'd2.value >= ? AND d.doc_id = d0.doc_id AND d0.field_name = ? AND '
            'd0.value <= ? AND d.doc_id = d1.doc_id AND d1.field_name = ? AND '
            'd1.value <= ? AND d.doc_id = d2.doc_id AND d2.field_name = ? AND '
            'd2.value <= ? GROUP BY d.doc_id, d.doc_rev, d.content ORDER BY '
            'd0.value, d1.value, d2.value;',
            ['key1', 'a', 'key2', 'b', 'key3', 'c', 'key1', 'p', 'key2', 'q',
             'key3', 'r'],
            ["key1", "key2", "key3"], ["a", "b", "c"], ["p", "q", "r"])

    def test__format_range_query_no_start(self):
        self.assertFormatRangeQueryEquals(
            'SELECT d.doc_id, d.doc_rev, d.content, count(c.doc_rev) FROM '
            'document d, document_fields d0, document_fields d1, '
            'document_fields d2 LEFT OUTER JOIN conflicts c ON c.doc_id = '
            'd.doc_id WHERE d.doc_id = d0.doc_id AND d0.field_name = ? AND '
            'd0.value <= ? AND d.doc_id = d1.doc_id AND d1.field_name = ? AND '
            'd1.value <= ? AND d.doc_id = d2.doc_id AND d2.field_name = ? AND '
            'd2.value <= ? GROUP BY d.doc_id, d.doc_rev, d.content ORDER BY '
            'd0.value, d1.value, d2.value;',
            ['key1', 'a', 'key2', 'b', 'key3', 'c'],
            ["key1", "key2", "key3"], None, ["a", "b", "c"])

    def test__format_range_query_no_end(self):
        self.assertFormatRangeQueryEquals(
            'SELECT d.doc_id, d.doc_rev, d.content, count(c.doc_rev) FROM '
            'document d, document_fields d0, document_fields d1, '
            'document_fields d2 LEFT OUTER JOIN conflicts c ON c.doc_id = '
            'd.doc_id WHERE d.doc_id = d0.doc_id AND d0.field_name = ? AND '
            'd0.value >= ? AND d.doc_id = d1.doc_id AND d1.field_name = ? AND '
            'd1.value >= ? AND d.doc_id = d2.doc_id AND d2.field_name = ? AND '
            'd2.value >= ? GROUP BY d.doc_id, d.doc_rev, d.content ORDER BY '
            'd0.value, d1.value, d2.value;',
            ['key1', 'a', 'key2', 'b', 'key3', 'c'],
            ["key1", "key2", "key3"], ["a", "b", "c"], None)

    def test__format_range_query_wildcard(self):
        self.assertFormatRangeQueryEquals(
            'SELECT d.doc_id, d.doc_rev, d.content, count(c.doc_rev) FROM '
            'document d, document_fields d0, document_fields d1, '
            'document_fields d2 LEFT OUTER JOIN conflicts c ON c.doc_id = '
            'd.doc_id WHERE d.doc_id = d0.doc_id AND d0.field_name = ? AND '
            'd0.value >= ? AND d.doc_id = d1.doc_id AND d1.field_name = ? AND '
            'd1.value >= ? AND d.doc_id = d2.doc_id AND d2.field_name = ? AND '
            'd2.value NOT NULL AND d.doc_id = d0.doc_id AND d0.field_name = ? '
            'AND d0.value <= ? AND d.doc_id = d1.doc_id AND d1.field_name = ? '
            'AND (d1.value < ? OR d1.value GLOB ?) AND d.doc_id = d2.doc_id '
            'AND d2.field_name = ? AND d2.value NOT NULL GROUP BY d.doc_id, '
            'd.doc_rev, d.content ORDER BY d0.value, d1.value, d2.value;',
            ['key1', 'a', 'key2', 'b', 'key3', 'key1', 'p', 'key2', 'q', 'q*',
             'key3'],
            ["key1", "key2", "key3"], ["a", "b*", "*"], ["p", "q*", "*"])


# -----------------------------------------------------------------------------
# The following tests come from `u1db.tests.test_open`.
# -----------------------------------------------------------------------------


class SQLCipherOpen(test_open.TestU1DBOpen):

    def test_open_no_create(self):
        self.assertRaises(errors.DatabaseDoesNotExist,
                          sqlcipher_open, self.db_path,
                          PASSWORD,
                          create=False)
        self.assertFalse(os.path.exists(self.db_path))

    def test_open_create(self):
        db = sqlcipher_open(self.db_path, PASSWORD, create=True)
        self.addCleanup(db.close)
        self.assertTrue(os.path.exists(self.db_path))
        self.assertIsInstance(db, SQLCipherDatabase)

    def test_open_with_factory(self):
        db = sqlcipher_open(self.db_path, PASSWORD, create=True,
                            document_factory=TestAlternativeDocument)
        self.addCleanup(db.close)
        doc = db.create_doc({})
        self.assertTrue(isinstance(doc, SoledadDocument))

    def test_open_existing(self):
        db = sqlcipher_open(self.db_path, PASSWORD)
        self.addCleanup(db.close)
        doc = db.create_doc_from_json(tests.simple_doc)
        # Even though create=True, we shouldn't wipe the db
        db2 = sqlcipher_open(self.db_path, PASSWORD, create=True)
        self.addCleanup(db2.close)
        doc2 = db2.get_doc(doc.doc_id)
        self.assertEqual(doc, doc2)

    def test_open_existing_no_create(self):
        db = sqlcipher_open(self.db_path, PASSWORD)
        self.addCleanup(db.close)
        db2 = sqlcipher_open(self.db_path, PASSWORD, create=False)
        self.addCleanup(db2.close)
        self.assertIsInstance(db2, SQLCipherDatabase)


# -----------------------------------------------------------------------------
# Tests for actual encryption of the database
# -----------------------------------------------------------------------------

class SQLCipherEncryptionTests(BaseSoledadTest):

    """
    Tests to guarantee SQLCipher is indeed encrypting data when storing.
    """

    def _delete_dbfiles(self):
        for dbfile in [self.DB_FILE]:
            if os.path.exists(dbfile):
                os.unlink(dbfile)

    def setUp(self):
        # the following come from BaseLeapTest.setUpClass, because
        # twisted.trial doesn't support such class methods for setting up
        # test classes.
        self.old_path = os.environ['PATH']
        self.old_home = os.environ['HOME']
        self.tempdir = tempfile.mkdtemp(prefix="leap_tests-")
        self.home = self.tempdir
        bin_tdir = os.path.join(
            self.tempdir,
            'bin')
        os.environ["PATH"] = bin_tdir
        os.environ["HOME"] = self.tempdir
        # this is our own stuff
        self.DB_FILE = os.path.join(self.tempdir, 'test.db')
        self._delete_dbfiles()

    def tearDown(self):
        self._delete_dbfiles()
        # the following come from BaseLeapTest.tearDownClass, because
        # twisted.trial doesn't support such class methods for tearing down
        # test classes.
        os.environ["PATH"] = self.old_path
        os.environ["HOME"] = self.old_home
        # safety check! please do not wipe my home...
        # XXX needs to adapt to non-linuces
        soledad_assert(
            self.tempdir.startswith('/tmp/leap_tests-') or
            self.tempdir.startswith('/var/folder'),
            "beware! tried to remove a dir which does not "
            "live in temporal folder!")
        shutil.rmtree(self.tempdir)

    def test_try_to_open_encrypted_db_with_sqlite_backend(self):
        """
        SQLite backend should not succeed to open SQLCipher databases.
        """
        db = sqlcipher_open(self.DB_FILE, PASSWORD)
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
            db = sqlcipher_open(self.DB_FILE, PASSWORD)
            doc = db.get_doc(doc.doc_id)
            self.assertEqual(tests.simple_doc, doc.get_json(),
                             'decrypted content mismatch')
            db.close()

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
            db = sqlcipher_open(self.DB_FILE, PASSWORD)
            db.close()
            raise dbapi2.DatabaseError(
                "SQLCipher backend should not be able to open non-encrypted "
                "dbs.")
        except DatabaseIsNotEncrypted:
            pass
