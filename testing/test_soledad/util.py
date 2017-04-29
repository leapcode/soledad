# -*- CODING: UTF-8 -*-
# util.py
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
Utilities used by multiple test suites.
"""

import os
import random
import string
import couchdb
import pytest
import sys

from six.moves.urllib.parse import urljoin
from six import StringIO
from uuid import uuid4
from mock import Mock

from twisted.trial import unittest

from leap.common.testing.basetest import BaseLeapTest

from leap.soledad.common import l2db
from leap.soledad.common.l2db import sync
from leap.soledad.common.l2db.remote import http_database

from leap.soledad.common.document import SoledadDocument
from leap.soledad.common.couch import CouchDatabase
from leap.soledad.common.couch.state import CouchServerState

from leap.soledad.client import Soledad
from leap.soledad.client import http_target
from leap.soledad.client import auth
from leap.soledad.client._crypto import is_symmetrically_encrypted
from leap.soledad.client._database.sqlcipher import SQLCipherDatabase
from leap.soledad.client._database.sqlcipher import SQLCipherOptions

from leap.soledad.server import SoledadApp

if sys.version_info[0] < 3:
    from pysqlcipher import dbapi2
else:
    from pysqlcipher3 import dbapi2


PASSWORD = '123456'
ADDRESS = 'user-1234'


def make_local_db_and_target(test):
    db = test.create_database('test')
    st = db.get_sync_target()
    return db, st


def make_document_for_test(test, doc_id, rev, content, has_conflicts=False):
    return SoledadDocument(doc_id, rev, content, has_conflicts=has_conflicts)


def make_sqlcipher_database_for_test(test, replica_uid):
    db = SQLCipherDatabase(
        SQLCipherOptions(':memory:', PASSWORD))
    db._set_replica_uid(replica_uid)
    return db


def copy_sqlcipher_database_for_test(test, db):
    # DO NOT COPY OR REUSE THIS CODE OUTSIDE TESTS: COPYING U1DB DATABASES IS
    # THE WRONG THING TO DO, THE ONLY REASON WE DO SO HERE IS TO TEST THAT WE
    # CORRECTLY DETECT IT HAPPENING SO THAT WE CAN RAISE ERRORS RATHER THAN
    # CORRUPT USER DATA. USE SYNC INSTEAD, OR WE WILL SEND NINJA TO YOUR
    # HOUSE.
    new_db = make_sqlcipher_database_for_test(test, None)
    tmpfile = StringIO()
    for line in db._db_handle.iterdump():
        if 'sqlite_sequence' not in line:  # work around bug in iterdump
            tmpfile.write('%s\n' % line)
    tmpfile.seek(0)
    new_db._db_handle = dbapi2.connect(':memory:')
    new_db._db_handle.cursor().executescript(tmpfile.read())
    new_db._db_handle.commit()
    new_db._set_replica_uid(db._replica_uid)
    new_db._factory = db._factory
    return new_db


SQLCIPHER_SCENARIOS = [
    ('sqlcipher', {'make_database_for_test': make_sqlcipher_database_for_test,
                   'copy_database_for_test': copy_sqlcipher_database_for_test,
                   'make_document_for_test': make_document_for_test, }),
]


def make_soledad_app(state):
    return SoledadApp(state)


def make_token_soledad_app(state):
    application = SoledadApp(state)

    def _verify_authentication_data(uuid, auth_data):
        if uuid.startswith('user-') and auth_data == 'auth-token':
            return True
        return False

    # we test for action authorization in leap.soledad.common.tests.test_server
    def _verify_authorization(uuid, environ):
        return True

    application._verify_authentication_data = _verify_authentication_data
    application._verify_authorization = _verify_authorization
    return application


def make_soledad_document_for_test(test, doc_id, rev, content,
                                   has_conflicts=False):
    return SoledadDocument(
        doc_id, rev, content, has_conflicts=has_conflicts)


def make_token_http_database_for_test(test, replica_uid):
    test.startServer()
    test.request_state._create_database(replica_uid)

    class _HTTPDatabaseWithToken(
            http_database.HTTPDatabase, auth.TokenBasedAuth):

        def set_token_credentials(self, uuid, token):
            auth.TokenBasedAuth.set_token_credentials(self, uuid, token)

        def _sign_request(self, method, url_query, params):
            return auth.TokenBasedAuth._sign_request(
                self, method, url_query, params)

    http_db = _HTTPDatabaseWithToken(test.getURL('test'))
    http_db.set_token_credentials('user-uuid', 'auth-token')
    return http_db


def copy_token_http_database_for_test(test, db):
    # DO NOT COPY OR REUSE THIS CODE OUTSIDE TESTS: COPYING U1DB DATABASES IS
    # THE WRONG THING TO DO, THE ONLY REASON WE DO SO HERE IS TO TEST THAT WE
    # CORRECTLY DETECT IT HAPPENING SO THAT WE CAN RAISE ERRORS RATHER THAN
    # CORRUPT USER DATA. USE SYNC INSTEAD, OR WE WILL SEND NINJA TO YOUR
    # HOUSE.
    http_db = test.request_state._copy_database(db)
    http_db.set_token_credentials(http_db, 'user-uuid', 'auth-token')
    return http_db


def sync_via_synchronizer(test, db_source, db_target, trace_hook=None,
                          trace_hook_shallow=None):
    target = db_target.get_sync_target()
    trace_hook = trace_hook or trace_hook_shallow
    if trace_hook:
        target._set_trace_hook(trace_hook)
    return sync.Synchronizer(db_source, target).sync()


class MockedSharedDBTest(object):

    def get_default_shared_mock(self, put_doc_side_effect=None,
                                get_doc_return_value=None):
        """
        Get a default class for mocking the shared DB
        """
        class defaultMockSharedDB(object):
            get_doc = Mock(return_value=get_doc_return_value)
            put_doc = Mock(side_effect=put_doc_side_effect)
            open = Mock(return_value=None)
            close = Mock(return_value=None)

            def __call__(self):
                return self
        return defaultMockSharedDB


def soledad_sync_target(
        test, path, source_replica_uid=uuid4().hex):
    creds = {'token': {
        'uuid': 'user-uuid',
        'token': 'auth-token',
    }}
    return http_target.SoledadHTTPSyncTarget(
        test.getURL(path),
        source_replica_uid,
        creds,
        test._soledad._crypto,
        None)  # cert_file


# redefine the base leap test class so it inherits from twisted trial's
# TestCase. This is needed so trial knows that it has to manage a reactor and
# wait for deferreds returned by tests to be fired.

BaseLeapTest = type(
    'BaseLeapTest', (unittest.TestCase,), dict(BaseLeapTest.__dict__))


class BaseSoledadTest(BaseLeapTest, MockedSharedDBTest):

    """
    Instantiates Soledad for usage in tests.
    """

    @pytest.mark.usefixtures("method_tmpdir")
    def setUp(self):
        # The following snippet comes from BaseLeapTest.setUpClass, but we
        # repeat it here because twisted.trial does not work with
        # setUpClass/tearDownClass.

        self.home = self.tempdir

        # config info
        self.db1_file = os.path.join(self.tempdir, "db1.u1db")
        self.db2_file = os.path.join(self.tempdir, "db2.u1db")
        self.email = ADDRESS
        # open test dbs
        self._db1 = l2db.open(self.db1_file, create=True,
                              document_factory=SoledadDocument)
        self._db2 = l2db.open(self.db2_file, create=True,
                              document_factory=SoledadDocument)
        # get a random prefix for each test, so we do not mess with
        # concurrency during initialization and shutting down of
        # each local db.
        self.rand_prefix = ''.join(
            map(lambda x: random.choice(string.ascii_letters), range(6)))

        # initialize soledad by hand so we can control keys
        # XXX check if this soledad is actually used
        self._soledad = self._soledad_instance(
            prefix=self.rand_prefix, user=self.email)

    def tearDown(self):
        self._db1.close()
        self._db2.close()
        self._soledad.close()

        def _delete_temporary_dirs():
            # XXX should not access "private" attrs
            for f in [self._soledad.local_db_path,
                      self._soledad.secrets.secrets_path]:
                if os.path.isfile(f):
                    os.unlink(f)

        from twisted.internet import reactor
        reactor.addSystemEventTrigger(
            "after", "shutdown", _delete_temporary_dirs)

    def _soledad_instance(self, user=ADDRESS, passphrase=u'123',
                          prefix='',
                          secrets_path='secrets.json',
                          local_db_path='soledad.u1db',
                          server_url='https://127.0.0.1/',
                          cert_file=None,
                          shared_db_class=None,
                          auth_token='auth-token'):

        def _put_doc_side_effect(doc):
            self._doc_put = doc

        if shared_db_class is not None:
            MockSharedDB = shared_db_class
        else:
            MockSharedDB = self.get_default_shared_mock(
                _put_doc_side_effect)

        soledad = Soledad(
            user,
            passphrase,
            secrets_path=os.path.join(
                self.tempdir, prefix, secrets_path),
            local_db_path=os.path.join(
                self.tempdir, prefix, local_db_path),
            server_url=server_url,  # Soledad will fail if not given an url
            cert_file=cert_file,
            shared_db=MockSharedDB(),
            auth_token=auth_token)
        self.addCleanup(soledad.close)
        return soledad

    @pytest.inlineCallbacks
    def assertGetEncryptedDoc(
            self, db, doc_id, doc_rev, content, has_conflicts):
        """
        Assert that the document in the database looks correct.
        """
        exp_doc = self.make_document(doc_id, doc_rev, content,
                                     has_conflicts=has_conflicts)
        doc = db.get_doc(doc_id)

        if is_symmetrically_encrypted(doc.content['raw']):
            crypt = self._soledad._crypto
            decrypted = yield crypt.decrypt_doc(doc)
            doc.set_json(decrypted)
        self.assertEqual(exp_doc.doc_id, doc.doc_id)
        self.assertEqual(exp_doc.rev, doc.rev)
        self.assertEqual(exp_doc.has_conflicts, doc.has_conflicts)
        self.assertEqual(exp_doc.content, doc.content)


@pytest.mark.usefixtures("couch_url")
class CouchDBTestCase(unittest.TestCase, MockedSharedDBTest):

    """
    TestCase base class for tests against a real CouchDB server.
    """

    def setUp(self):
        """
        Make sure we have a CouchDB instance for a test.
        """
        self.couch_server = couchdb.Server(self.couch_url)

    def delete_db(self, name):
        try:
            self.couch_server.delete(name)
        except:
            # ignore if already missing
            pass


class CouchServerStateForTests(CouchServerState):

    """
    This is a slightly modified CouchDB server state that allows for creating
    a database.

    Ordinarily, the CouchDB server state does not allow some operations,
    because for security purposes the Soledad Server should not even have
    enough permissions to perform them. For tests, we allow database creation,
    otherwise we'd have to create those databases in setUp/tearDown methods,
    which is less pleasant than allowing the db to be automatically created.
    """

    def __init__(self, *args, **kwargs):
        self.dbs = []
        super(CouchServerStateForTests, self).__init__(*args, **kwargs)

    def _create_database(self, replica_uid=None, dbname=None):
        """
        Create db and append to a list, allowing test to close it later
        """
        dbname = dbname or ('test-%s' % uuid4().hex)
        db = CouchDatabase.open_database(
            urljoin(self.couch_url, dbname),
            True,
            replica_uid=replica_uid or 'test')
        self.dbs.append(db)
        return db

    def ensure_database(self, dbname):
        db = self._create_database(dbname=dbname)
        return db, db.replica_uid


class SoledadWithCouchServerMixin(
        BaseSoledadTest,
        CouchDBTestCase):

    def setUp(self):
        CouchDBTestCase.setUp(self)
        BaseSoledadTest.setUp(self)
        main_test_class = getattr(self, 'main_test_class', None)
        if main_test_class is not None:
            main_test_class.setUp(self)

    def tearDown(self):
        main_test_class = getattr(self, 'main_test_class', None)
        if main_test_class is not None:
            main_test_class.tearDown(self)
        # delete the test database
        BaseSoledadTest.tearDown(self)
        CouchDBTestCase.tearDown(self)

    def make_app(self):
        self.request_state = CouchServerStateForTests(self.couch_url)
        self.addCleanup(self.delete_dbs)
        return self.make_app_with_state(self.request_state)

    def delete_dbs(self):
        for db in self.request_state.dbs:
            self.delete_db(db._dbname)
