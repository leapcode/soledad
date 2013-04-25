"""Test ObjectStore backend bits.

For these tests to run, a couch server has to be running on (default) port
5984.
"""

import re
import copy
from base64 import b64decode
from leap.soledad.backends import couch
from leap.soledad.tests import u1db_tests as tests
from leap.soledad.tests.u1db_tests import test_backends
from leap.soledad.tests.u1db_tests import test_sync
try:
    import simplejson as json
except ImportError:
    import json  # noqa
from leap.soledad.backends.leap_backend import (
    LeapDocument,
)


#-----------------------------------------------------------------------------
# A wrapper for running couchdb locally.
#-----------------------------------------------------------------------------

import re
import os
import tempfile
import subprocess
import time
import unittest


# from: https://github.com/smcq/paisley/blob/master/paisley/test/util.py
# TODO: include license of above project.
class CouchDBWrapper(object):
    """
    Wrapper for external CouchDB instance which is started and stopped for
    testing.
    """

    def start(self):
        """
        Start a CouchDB instance for a test.
        """
        self.tempdir = tempfile.mkdtemp(suffix='.couch.test')

        path = os.path.join(os.path.dirname(__file__),
                            'couchdb.ini.template')
        handle = open(path)
        conf = handle.read() % {
            'tempdir': self.tempdir,
        }
        handle.close()

        confPath = os.path.join(self.tempdir, 'test.ini')
        handle = open(confPath, 'w')
        handle.write(conf)
        handle.close()

        # create the dirs from the template
        os.mkdir(os.path.join(self.tempdir, 'lib'))
        os.mkdir(os.path.join(self.tempdir, 'log'))
        args = ['couchdb', '-n', '-a', confPath]
        #null = open('/dev/null', 'w')
        self.process = subprocess.Popen(
            args, env=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            close_fds=True)
        # find port
        logPath = os.path.join(self.tempdir, 'log', 'couch.log')
        while not os.path.exists(logPath):
            if self.process.poll() is not None:
                raise Exception("""
couchdb exited with code %d.
stdout:
%s
stderr:
%s""" % (
                    self.process.returncode, self.process.stdout.read(),
                    self.process.stderr.read()))
            time.sleep(0.01)
        while os.stat(logPath).st_size == 0:
            time.sleep(0.01)
        PORT_RE = re.compile(
            'Apache CouchDB has started on http://127.0.0.1:(?P<port>\d+)')

        handle = open(logPath)
        line = handle.read()
        handle.close()
        m = PORT_RE.search(line)
        if not m:
            self.stop()
            raise Exception("Cannot find port in line %s" % line)
        self.port = int(m.group('port'))

    def stop(self):
        """
        Terminate the CouchDB instance.
        """
        self.process.terminate()
        self.process.communicate()
        os.system("rm -rf %s" % self.tempdir)


class CouchDBTestCase(unittest.TestCase):
    """
    TestCase base class for tests against a real CouchDB server.
    """

    def setUp(self):
        """
        Make sure we have a CouchDB instance for a test.
        """
        self.wrapper = CouchDBWrapper()
        self.wrapper.start()
        #self.db = self.wrapper.db
        unittest.TestCase.setUp(self)

    def tearDown(self):
        """
        Stop CouchDB instance for test.
        """
        self.wrapper.stop()
        unittest.TestCase.tearDown(self)


#-----------------------------------------------------------------------------
# The following tests come from `u1db.tests.test_common_backend`.
#-----------------------------------------------------------------------------

class TestCouchBackendImpl(CouchDBTestCase):

    def test__allocate_doc_id(self):
        db = couch.CouchDatabase('http://localhost:' + str(self.wrapper.port),
                                 'u1db_tests')
        doc_id1 = db._allocate_doc_id()
        self.assertTrue(doc_id1.startswith('D-'))
        self.assertEqual(34, len(doc_id1))
        int(doc_id1[len('D-'):], 16)
        self.assertNotEqual(doc_id1, db._allocate_doc_id())


#-----------------------------------------------------------------------------
# The following tests come from `u1db.tests.test_backends`.
#-----------------------------------------------------------------------------

def make_couch_database_for_test(test, replica_uid):
    port = str(test.wrapper.port)
    return couch.CouchDatabase('http://localhost:' + port, replica_uid,
                               replica_uid=replica_uid or 'test')


def copy_couch_database_for_test(test, db):
    port = str(test.wrapper.port)
    new_db = couch.CouchDatabase('http://localhost:' + port,
                                 db._replica_uid + '_copy',
                                 replica_uid=db._replica_uid or 'test')
    gen, docs = db.get_all_docs(include_deleted=True)
    for doc in docs:
        new_db._put_doc(doc)
    new_db._transaction_log = copy.deepcopy(db._transaction_log)
    new_db._conflicts = copy.deepcopy(db._conflicts)
    new_db._other_generations = copy.deepcopy(db._other_generations)
    new_db._indexes = copy.deepcopy(db._indexes)
    new_db._store_u1db_data()
    return new_db


def make_document_for_test(test, doc_id, rev, content, has_conflicts=False):
    return LeapDocument(doc_id, rev, content, has_conflicts=has_conflicts)


COUCH_SCENARIOS = [
    ('couch', {'make_database_for_test': make_couch_database_for_test,
               'copy_database_for_test': copy_couch_database_for_test,
               'make_document_for_test': make_document_for_test, }),
]


class CouchTests(test_backends.AllDatabaseTests, CouchDBTestCase):

    scenarios = COUCH_SCENARIOS

    def tearDown(self):
        self.db.delete_database()
        test_backends.AllDatabaseTests.tearDown(self)


class CouchDatabaseTests(test_backends.LocalDatabaseTests, CouchDBTestCase):

    scenarios = COUCH_SCENARIOS

    def tearDown(self):
        self.db.delete_database()
        test_backends.LocalDatabaseTests.tearDown(self)


class CouchValidateGenNTransIdTests(
        test_backends.LocalDatabaseValidateGenNTransIdTests, CouchDBTestCase):

    scenarios = COUCH_SCENARIOS

    def tearDown(self):
        self.db.delete_database()
        test_backends.LocalDatabaseValidateGenNTransIdTests.tearDown(self)


class CouchValidateSourceGenTests(
        test_backends.LocalDatabaseValidateSourceGenTests, CouchDBTestCase):

    scenarios = COUCH_SCENARIOS

    def tearDown(self):
        self.db.delete_database()
        test_backends.LocalDatabaseValidateSourceGenTests.tearDown(self)


class CouchWithConflictsTests(
        test_backends.LocalDatabaseWithConflictsTests, CouchDBTestCase):

    scenarios = COUCH_SCENARIOS

    def tearDown(self):
        self.db.delete_database()
        test_backends.LocalDatabaseWithConflictsTests.tearDown(self)


# Notice: the CouchDB backend is currently used for storing encrypted data in
# the server, so indexing makes no sense. Thus, we ignore index testing for
# now.

class CouchIndexTests(test_backends.DatabaseIndexTests, CouchDBTestCase):

    scenarios = COUCH_SCENARIOS

    def tearDown(self):
        self.db.delete_database()
        test_backends.DatabaseIndexTests.tearDown(self)


#-----------------------------------------------------------------------------
# The following tests come from `u1db.tests.test_sync`.
#-----------------------------------------------------------------------------

target_scenarios = [
    ('local', {'create_db_and_target': test_sync._make_local_db_and_target}), ]


simple_doc = tests.simple_doc
nested_doc = tests.nested_doc


class CouchDatabaseSyncTargetTests(test_sync.DatabaseSyncTargetTests,
                                   CouchDBTestCase):

    scenarios = (tests.multiply_scenarios(COUCH_SCENARIOS, target_scenarios))

    def tearDown(self):
        self.db.delete_database()
        test_sync.DatabaseSyncTargetTests.tearDown(self)

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


sync_scenarios = []
for name, scenario in COUCH_SCENARIOS:
    scenario = dict(scenario)
    scenario['do_sync'] = test_sync.sync_via_synchronizer
    sync_scenarios.append((name, scenario))
    scenario = dict(scenario)


class CouchDatabaseSyncTests(test_sync.DatabaseSyncTests, CouchDBTestCase):

    scenarios = sync_scenarios

    def setUp(self):
        self.db = None
        self.db1 = None
        self.db2 = None
        self.db3 = None
        test_sync.DatabaseSyncTests.setUp(self)
        CouchDBTestCase.setUp(self)

    def tearDown(self):
        self.db and self.db.delete_database()
        self.db1 and self.db1.delete_database()
        self.db2 and self.db2.delete_database()
        self.db3 and self.db3.delete_database()
        db = self.create_database('test1_copy', 'source')
        db.delete_database()
        db = self.create_database('test2_copy', 'target')
        db.delete_database()
        db = self.create_database('test3', 'target')
        db.delete_database()
        test_sync.DatabaseSyncTests.tearDown(self)


#-----------------------------------------------------------------------------
# The following tests test extra functionality introduced by our backends
#-----------------------------------------------------------------------------

class CouchDatabaseStorageTests(CouchDBTestCase):

    def _listify(self, l):
        if type(l) is dict:
            return {
                self._listify(a): self._listify(b) for a, b in l.iteritems()}
        if hasattr(l, '__iter__'):
            return [self._listify(i) for i in l]
        return l

    def _fetch_u1db_data(self, db):
        cdoc = db._database.get(db.U1DB_DATA_DOC_ID)
        jsonstr = db._database.get_attachment(cdoc, 'u1db_json').getvalue()
        return json.loads(jsonstr)

    def test_transaction_log_storage_after_put(self):
        db = couch.CouchDatabase('http://localhost:' + str(self.wrapper.port),
                                 'u1db_tests')
        db.create_doc({'simple': 'doc'})
        content = self._fetch_u1db_data(db)
        self.assertEqual(
            self._listify(db._transaction_log),
            self._listify(content['transaction_log']))

    def test_conflict_log_storage_after_put_if_newer(self):
        db = couch.CouchDatabase('http://localhost:' + str(self.wrapper.port),
                                 'u1db_tests')
        doc = db.create_doc({'simple': 'doc'})
        doc.set_json(nested_doc)
        doc.rev = db._replica_uid + ':2'
        db._force_doc_sync_conflict(doc)
        content = self._fetch_u1db_data(db)
        self.assertEqual(
            self._listify(db._conflicts),
            self._listify(json.loads(b64decode(content['conflicts']))))

    def test_other_gens_storage_after_set(self):
        db = couch.CouchDatabase('http://localhost:' + str(self.wrapper.port),
                                 'u1db_tests')
        doc = db.create_doc({'simple': 'doc'})
        db._set_replica_gen_and_trans_id('a', 'b', 'c')
        content = self._fetch_u1db_data(db)
        self.assertEqual(
            self._listify(db._other_generations),
            self._listify(content['other_generations']))

    def test_index_storage_after_create(self):
        db = couch.CouchDatabase('http://localhost:' + str(self.wrapper.port),
                                 'u1db_tests')
        doc = db.create_doc({'name': 'john'})
        db.create_index('myindex', 'name')
        content = self._fetch_u1db_data(db)
        myind = db._indexes['myindex']
        index = {
            'myindex': {
                'definition': myind._definition,
                'name': myind._name,
                'values': myind._values,
            }
        }
        self.assertEqual(self._listify(index),
                         self._listify(
                             json.loads(b64decode(content['indexes']))))

    def test_index_storage_after_delete(self):
        db = couch.CouchDatabase('http://localhost:' + str(self.wrapper.port),
                                 'u1db_tests')
        doc = db.create_doc({'name': 'john'})
        db.create_index('myindex', 'name')
        db.create_index('myindex2', 'name')
        db.delete_index('myindex')
        content = self._fetch_u1db_data(db)
        myind = db._indexes['myindex2']
        index = {
            'myindex2': {
                'definition': myind._definition,
                'name': myind._name,
                'values': myind._values,
            }
        }
        self.assertEqual(self._listify(index),
                         self._listify(
                             json.loads(b64decode(content['indexes']))))

    def test_replica_uid_storage_after_db_creation(self):
        db = couch.CouchDatabase('http://localhost:' + str(self.wrapper.port),
                                 'u1db_tests')
        content = self._fetch_u1db_data(db)
        self.assertEqual(db._replica_uid, content['replica_uid'])


load_tests = tests.load_with_scenarios
