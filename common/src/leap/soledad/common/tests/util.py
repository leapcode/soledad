# -*- coding: utf-8 -*-
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


import tempfile
import shutil
from urlparse import urljoin

from StringIO import StringIO
from pysqlcipher import dbapi2
from u1db.errors import DatabaseDoesNotExist


from leap.soledad.common import soledad_assert
from leap.soledad.common.couch import CouchDatabase, CouchServerState
from leap.soledad.server import SoledadApp
from leap.soledad.server.auth import SoledadTokenAuthMiddleware


from leap.soledad.common.tests import u1db_tests as tests, BaseSoledadTest
from leap.soledad.common.tests.test_couch import CouchDBWrapper, CouchDBTestCase


from leap.soledad.client.sqlcipher import SQLCipherDatabase


PASSWORD = '123456'


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
    new_db = SQLCipherDatabase(':memory:', PASSWORD)
    tmpfile = StringIO()
    for line in db._db_handle.iterdump():
        if not 'sqlite_sequence' in line:  # work around bug in iterdump
            tmpfile.write('%s\n' % line)
    tmpfile.seek(0)
    new_db._db_handle = dbapi2.connect(':memory:')
    new_db._db_handle.cursor().executescript(tmpfile.read())
    new_db._db_handle.commit()
    new_db._set_replica_uid(db._replica_uid)
    new_db._factory = db._factory
    return new_db


def make_soledad_app(state):
    return SoledadApp(state)


def make_token_soledad_app(state):
    app = SoledadApp(state)

    def _verify_authentication_data(uuid, auth_data):
        if uuid == 'user-uuid' and auth_data == 'auth-token':
            return True
        return False

    # we test for action authorization in leap.soledad.common.tests.test_server
    def _verify_authorization(uuid, environ):
        return True

    application = SoledadTokenAuthMiddleware(app)
    application._verify_authentication_data = _verify_authentication_data
    application._verify_authorization = _verify_authorization
    return application


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

    def _create_database(self, dbname):
        return CouchDatabase.open_database(
            urljoin(self._couch_url, dbname),
            True,
            replica_uid=dbname,
            ensure_ddocs=True)

    def ensure_database(self, dbname):
        db = self._create_database(dbname)
        return db, db.replica_uid


class SoledadWithCouchServerMixin(
        BaseSoledadTest,
        CouchDBTestCase):

    @classmethod
    def setUpClass(cls):
        """
        Make sure we have a CouchDB instance for a test.
        """
        # from BaseLeapTest
        cls.tempdir = tempfile.mkdtemp(prefix="leap_tests-")
        # from CouchDBTestCase
        cls.wrapper = CouchDBWrapper()
        cls.wrapper.start()
        #self.db = self.wrapper.db

    @classmethod
    def tearDownClass(cls):
        """
        Stop CouchDB instance for test.
        """
        # from BaseLeapTest
        soledad_assert(
            cls.tempdir.startswith('/tmp/leap_tests-'),
            "beware! tried to remove a dir which does not "
            "live in temporal folder!")
        shutil.rmtree(cls.tempdir)
        # from CouchDBTestCase
        cls.wrapper.stop()

    def setUp(self):
        BaseSoledadTest.setUp(self)
        CouchDBTestCase.setUp(self)
        main_test_class = getattr(self, 'main_test_class', None)
        if main_test_class is not None:
            main_test_class.setUp(self)
        self._couch_url = 'http://localhost:%d' % self.wrapper.port

    def tearDown(self):
        BaseSoledadTest.tearDown(self)
        CouchDBTestCase.tearDown(self)
        main_test_class = getattr(self, 'main_test_class', None)
        if main_test_class is not None:
            main_test_class.tearDown(self)
        # delete the test database
        try:
            db = CouchDatabase(self._couch_url, 'test')
            db.delete_database()
        except DatabaseDoesNotExist:
            pass

    def make_app(self):
        couch_url = urljoin(
            'http://localhost:' + str(self.wrapper.port), 'tests')
        self.request_state = CouchServerStateForTests(
            couch_url, 'shared', 'tokens')
        return self.make_app_with_state(self.request_state)
