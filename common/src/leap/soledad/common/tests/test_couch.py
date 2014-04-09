# -*- coding: utf-8 -*-
# test_couch.py
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
Test ObjectStore and Couch backend bits.
"""

import re
import copy
import shutil
from base64 import b64decode
from mock import Mock
from urlparse import urljoin

from couchdb.client import Server
from u1db import errors as u1db_errors

from leap.common.files import mkdir_p

from leap.soledad.common.tests import u1db_tests as tests
from leap.soledad.common.tests.u1db_tests import test_backends
from leap.soledad.common.tests.u1db_tests import test_sync
from leap.soledad.common import couch, errors
import simplejson as json


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
        mkdir_p(os.path.join(self.tempdir, 'lib'))
        mkdir_p(os.path.join(self.tempdir, 'log'))
        args = ['couchdb', '-n', '-a', confPath]
        null = open('/dev/null', 'w')

        self.process = subprocess.Popen(
            args, env=None, stdout=null.fileno(), stderr=null.fileno(),
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
        shutil.rmtree(self.tempdir)


class CouchDBTestCase(unittest.TestCase):
    """
    TestCase base class for tests against a real CouchDB server.
    """

    @classmethod
    def setUpClass(cls):
        """
        Make sure we have a CouchDB instance for a test.
        """
        cls.wrapper = CouchDBWrapper()
        cls.wrapper.start()
        #self.db = self.wrapper.db

    @classmethod
    def tearDownClass(cls):
        """
        Stop CouchDB instance for test.
        """
        cls.wrapper.stop()


#-----------------------------------------------------------------------------
# The following tests come from `u1db.tests.test_common_backend`.
#-----------------------------------------------------------------------------

class TestCouchBackendImpl(CouchDBTestCase):

    def test__allocate_doc_id(self):
        db = couch.CouchDatabase.open_database(
            urljoin(
                'http://localhost:' + str(self.wrapper.port), 'u1db_tests'),
                create=True,
                ensure_ddocs=True)
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
    return couch.CouchDatabase.open_database(
        urljoin('http://localhost:' + port, replica_uid),
        create=True,
        replica_uid=replica_uid or 'test',
        ensure_ddocs=True)


def copy_couch_database_for_test(test, db):
    port = str(test.wrapper.port)
    couch_url = 'http://localhost:' + port
    new_dbname = db._replica_uid + '_copy'
    new_db = couch.CouchDatabase.open_database(
        urljoin(couch_url, new_dbname),
        create=True,
        replica_uid=db._replica_uid or 'test')
    # copy all docs
    old_couch_db = Server(couch_url)[db._replica_uid]
    new_couch_db = Server(couch_url)[new_dbname]
    for doc_id in old_couch_db:
        doc = old_couch_db.get(doc_id)
        # bypass u1db_config document
        if doc_id == 'u1db_config':
            pass
        # copy design docs
        elif doc_id.startswith('_design'):
            del doc['_rev']
            new_couch_db.save(doc)
        # copy u1db docs
        elif 'u1db_rev' in doc:
            new_doc = {
                '_id': doc['_id'],
                'u1db_transactions': doc['u1db_transactions'],
                'u1db_rev': doc['u1db_rev']
            }
            attachments = []
            if ('u1db_conflicts' in doc):
                new_doc['u1db_conflicts'] = doc['u1db_conflicts']
                for c_rev in doc['u1db_conflicts']:
                    attachments.append('u1db_conflict_%s' % c_rev)
            new_couch_db.save(new_doc)
            # save conflict data
            attachments.append('u1db_content')
            for att_name in attachments:
                att = old_couch_db.get_attachment(doc_id, att_name)
                if (att is not None):
                    new_couch_db.put_attachment(new_doc, att,
                                                filename=att_name)
    return new_db


def make_document_for_test(test, doc_id, rev, content, has_conflicts=False):
    return couch.CouchDocument(
        doc_id, rev, content, has_conflicts=has_conflicts)


COUCH_SCENARIOS = [
    ('couch', {'make_database_for_test': make_couch_database_for_test,
               'copy_database_for_test': copy_couch_database_for_test,
               'make_document_for_test': make_document_for_test, }),
]


class CouchTests(test_backends.AllDatabaseTests, CouchDBTestCase):

    scenarios = COUCH_SCENARIOS

    def setUp(self):
        test_backends.AllDatabaseTests.setUp(self)
        # save db info because of test_close
        self._url = self.db._url
        self._dbname = self.db._dbname

    def tearDown(self):
        # if current test is `test_close` we have to use saved objects to
        # delete the database because the close() method will have removed the
        # references needed to do it using the CouchDatabase.
        if self.id() == \
                'leap.soledad.common.tests.test_couch.CouchTests.' \
                'test_close(couch)':
            server = Server(url=self._url)
            del(server[self._dbname])
        else:
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


# Notice: the CouchDB backend does not have indexing capabilities, so we do
# not test indexing now.

#class CouchIndexTests(test_backends.DatabaseIndexTests, CouchDBTestCase):
#
#    scenarios = COUCH_SCENARIOS
#
#    def tearDown(self):
#        self.db.delete_database()
#        test_backends.DatabaseIndexTests.tearDown(self)


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

    def setUp(self):
        # we implement parents' setUp methods here to prevent from launching
        # more couch instances then needed.
        tests.TestCase.setUp(self)
        self.server = self.server_thread = None
        self.db, self.st = self.create_db_and_target(self)
        self.other_changes = []

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


# The following tests need that the database have an index, so we fake one.
old_class = couch.CouchDatabase

from u1db.backends.inmemory import InMemoryIndex


class IndexedCouchDatabase(couch.CouchDatabase):

    def __init__(self, url, dbname, replica_uid=None, ensure_ddocs=True,
            session=None):
        old_class.__init__(self, url, dbname, replica_uid=replica_uid, 
                           ensure_ddocs=ensure_ddocs, session=session)
        self._indexes = {}

    def _put_doc(self, old_doc, doc):
        for index in self._indexes.itervalues():
            if old_doc is not None and not old_doc.is_tombstone():
                index.remove_json(old_doc.doc_id, old_doc.get_json())
            if not doc.is_tombstone():
                index.add_json(doc.doc_id, doc.get_json())
        old_class._put_doc(self, old_doc, doc)

    def create_index(self, index_name, *index_expressions):
        if index_name in self._indexes:
            if self._indexes[index_name]._definition == list(
                    index_expressions):
                return
            raise u1db_errors.IndexNameTakenError
        index = InMemoryIndex(index_name, list(index_expressions))
        _, all_docs = self.get_all_docs()
        for doc in all_docs:
            index.add_json(doc.doc_id, doc.get_json())
        self._indexes[index_name] = index

    def delete_index(self, index_name):
        del self._indexes[index_name]

    def list_indexes(self):
        definitions = []
        for idx in self._indexes.itervalues():
            definitions.append((idx._name, idx._definition))
        return definitions

    def get_from_index(self, index_name, *key_values):
        try:
            index = self._indexes[index_name]
        except KeyError:
            raise u1db_errors.IndexDoesNotExist
        doc_ids = index.lookup(key_values)
        result = []
        for doc_id in doc_ids:
            result.append(self._get_doc(doc_id, check_for_conflicts=True))
        return result

    def get_range_from_index(self, index_name, start_value=None,
                             end_value=None):
        """Return all documents with key values in the specified range."""
        try:
            index = self._indexes[index_name]
        except KeyError:
            raise u1db_errors.IndexDoesNotExist
        if isinstance(start_value, basestring):
            start_value = (start_value,)
        if isinstance(end_value, basestring):
            end_value = (end_value,)
        doc_ids = index.lookup_range(start_value, end_value)
        result = []
        for doc_id in doc_ids:
            result.append(self._get_doc(doc_id, check_for_conflicts=True))
        return result

    def get_index_keys(self, index_name):
        try:
            index = self._indexes[index_name]
        except KeyError:
            raise u1db_errors.IndexDoesNotExist
        keys = index.keys()
        # XXX inefficiency warning
        return list(set([tuple(key.split('\x01')) for key in keys]))


couch.CouchDatabase = IndexedCouchDatabase

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


class CouchDatabaseExceptionsTests(CouchDBTestCase):

    def setUp(self):
        CouchDBTestCase.setUp(self)
        self.db = couch.CouchDatabase.open_database(
            urljoin('http://127.0.0.1:%d' % self.wrapper.port, 'test'),
            create=True,
            ensure_ddocs=False)  # note that we don't enforce ddocs here

    def tearDown(self):
        self.db.delete_database()

    def test_missing_design_doc_raises(self):
        """
        Test that all methods that access design documents will raise if the
        design docs are not present.
        """
        # _get_generation()
        self.assertRaises(
            errors.MissingDesignDocError,
            self.db._get_generation)
        # _get_generation_info()
        self.assertRaises(
            errors.MissingDesignDocError,
            self.db._get_generation_info)
        # _get_trans_id_for_gen()
        self.assertRaises(
            errors.MissingDesignDocError,
            self.db._get_trans_id_for_gen, 1)
        # _get_transaction_log()
        self.assertRaises(
            errors.MissingDesignDocError,
            self.db._get_transaction_log)
        # whats_changed()
        self.assertRaises(
            errors.MissingDesignDocError,
            self.db.whats_changed)
        # _do_set_replica_gen_and_trans_id()
        self.assertRaises(
            errors.MissingDesignDocError,
            self.db._do_set_replica_gen_and_trans_id, 1, 2, 3)

    def test_missing_design_doc_functions_raises(self):
        """
        Test that all methods that access design documents list functions
        will raise if the functions are not present.
        """
        self.db = couch.CouchDatabase.open_database(
            urljoin('http://127.0.0.1:%d' % self.wrapper.port, 'test'),
            create=True,
            ensure_ddocs=True)
        # erase views from _design/transactions
        transactions = self.db._database['_design/transactions']
        transactions['lists'] = {}
        self.db._database.save(transactions)
        # _get_generation()
        self.assertRaises(
            errors.MissingDesignDocListFunctionError,
            self.db._get_generation)
        # _get_generation_info()
        self.assertRaises(
            errors.MissingDesignDocListFunctionError,
            self.db._get_generation_info)
        # _get_trans_id_for_gen()
        self.assertRaises(
            errors.MissingDesignDocListFunctionError,
            self.db._get_trans_id_for_gen, 1)
        # whats_changed()
        self.assertRaises(
            errors.MissingDesignDocListFunctionError,
            self.db.whats_changed)

    def test_absent_design_doc_functions_raises(self):
        """
        Test that all methods that access design documents list functions
        will raise if the functions are not present.
        """
        self.db = couch.CouchDatabase.open_database(
            urljoin('http://127.0.0.1:%d' % self.wrapper.port, 'test'),
            create=True,
            ensure_ddocs=True)
        # erase views from _design/transactions
        transactions = self.db._database['_design/transactions']
        del transactions['lists']
        self.db._database.save(transactions)
        # _get_generation()
        self.assertRaises(
            errors.MissingDesignDocListFunctionError,
            self.db._get_generation)
        # _get_generation_info()
        self.assertRaises(
            errors.MissingDesignDocListFunctionError,
            self.db._get_generation_info)
        # _get_trans_id_for_gen()
        self.assertRaises(
            errors.MissingDesignDocListFunctionError,
            self.db._get_trans_id_for_gen, 1)
        # whats_changed()
        self.assertRaises(
            errors.MissingDesignDocListFunctionError,
            self.db.whats_changed)

    def test_missing_design_doc_named_views_raises(self):
        """
        Test that all methods that access design documents' named views  will
        raise if the views are not present.
        """
        self.db = couch.CouchDatabase.open_database(
            urljoin('http://127.0.0.1:%d' % self.wrapper.port, 'test'),
            create=True,
            ensure_ddocs=True)
        # erase views from _design/docs
        docs = self.db._database['_design/docs']
        del docs['views']
        self.db._database.save(docs)
        # erase views from _design/syncs
        syncs = self.db._database['_design/syncs']
        del syncs['views']
        self.db._database.save(syncs)
        # erase views from _design/transactions
        transactions = self.db._database['_design/transactions']
        del transactions['views']
        self.db._database.save(transactions)
        # _get_generation()
        self.assertRaises(
            errors.MissingDesignDocNamedViewError,
            self.db._get_generation)
        # _get_generation_info()
        self.assertRaises(
            errors.MissingDesignDocNamedViewError,
            self.db._get_generation_info)
        # _get_trans_id_for_gen()
        self.assertRaises(
            errors.MissingDesignDocNamedViewError,
            self.db._get_trans_id_for_gen, 1)
        # _get_transaction_log()
        self.assertRaises(
            errors.MissingDesignDocNamedViewError,
            self.db._get_transaction_log)
        # whats_changed()
        self.assertRaises(
            errors.MissingDesignDocNamedViewError,
            self.db.whats_changed)

    def test_deleted_design_doc_raises(self):
        """
        Test that all methods that access design documents will raise if the
        design docs are not present.
        """
        self.db = couch.CouchDatabase.open_database(
            urljoin('http://127.0.0.1:%d' % self.wrapper.port, 'test'),
            create=True,
            ensure_ddocs=True)
        # delete _design/docs
        del self.db._database['_design/docs']
        # delete _design/syncs
        del self.db._database['_design/syncs']
        # delete _design/transactions
        del self.db._database['_design/transactions']
        # _get_generation()
        self.assertRaises(
            errors.MissingDesignDocDeletedError,
            self.db._get_generation)
        # _get_generation_info()
        self.assertRaises(
            errors.MissingDesignDocDeletedError,
            self.db._get_generation_info)
        # _get_trans_id_for_gen()
        self.assertRaises(
            errors.MissingDesignDocDeletedError,
            self.db._get_trans_id_for_gen, 1)
        # _get_transaction_log()
        self.assertRaises(
            errors.MissingDesignDocDeletedError,
            self.db._get_transaction_log)
        # whats_changed()
        self.assertRaises(
            errors.MissingDesignDocDeletedError,
            self.db.whats_changed)
        # _do_set_replica_gen_and_trans_id()
        self.assertRaises(
            errors.MissingDesignDocDeletedError,
            self.db._do_set_replica_gen_and_trans_id, 1, 2, 3)


load_tests = tests.load_with_scenarios
