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


import os
import tempfile
import shutil
import random
import string
import u1db
import subprocess
import time
import re

from mock import Mock
from urlparse import urljoin
from StringIO import StringIO
from pysqlcipher import dbapi2

from u1db.errors import DatabaseDoesNotExist
from u1db.remote import http_database

from twisted.trial import unittest

from leap.common.files import mkdir_p

from leap.soledad.common import soledad_assert
from leap.soledad.common.document import SoledadDocument
from leap.soledad.common.couch import CouchDatabase, CouchServerState
from leap.soledad.common.crypto import ENC_SCHEME_KEY

from leap.soledad.client import Soledad
from leap.soledad.client import target
from leap.soledad.client import auth
from leap.soledad.client.crypto import decrypt_doc_dict

from leap.soledad.server import SoledadApp
from leap.soledad.server.auth import SoledadTokenAuthMiddleware

from leap.soledad.client.sqlcipher import (
    SQLCipherDatabase,
    SQLCipherOptions,
)


PASSWORD = '123456'
ADDRESS = 'leap@leap.se'


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


class MockedSharedDBTest(object):

    def get_default_shared_mock(self, put_doc_side_effect=None,
            get_doc_return_value=None):
        """
        Get a default class for mocking the shared DB
        """
        class defaultMockSharedDB(object):
            get_doc = Mock(return_value=get_doc_return_value)
            put_doc = Mock(side_effect=put_doc_side_effect)
            lock = Mock(return_value=('atoken', 300))
            unlock = Mock(return_value=True)
            open = Mock(return_value=None)
            syncable = True

            def __call__(self):
                return self
        return defaultMockSharedDB


def soledad_sync_target(test, path):
    return target.SoledadSyncTarget(
        test.getURL(path), crypto=test._soledad._crypto)


def token_soledad_sync_target(test, path):
    st = soledad_sync_target(test, path)
    st.set_token_credentials('user-uuid', 'auth-token')
    return st


class BaseSoledadTest(unittest.TestCase, MockedSharedDBTest):
    """
    Instantiates Soledad for usage in tests.
    """
    defer_sync_encryption = False

    def setUp(self):
        # The following snippet comes from BaseLeapTest.setUpClass, but we
        # repeat it here because twisted.trial does not work with
        # setUpClass/tearDownClass.
        self.old_path = os.environ['PATH']
        self.old_home = os.environ['HOME']
        self.tempdir = tempfile.mkdtemp(prefix="leap_tests-")
        self.home = self.tempdir
        bin_tdir = os.path.join(
            self.tempdir,
            'bin')
        os.environ["PATH"] = bin_tdir
        os.environ["HOME"] = self.tempdir

        # config info
        self.db1_file = os.path.join(self.tempdir, "db1.u1db")
        self.db2_file = os.path.join(self.tempdir, "db2.u1db")
        self.email = ADDRESS
        # open test dbs
        self._db1 = u1db.open(self.db1_file, create=True,
                              document_factory=SoledadDocument)
        self._db2 = u1db.open(self.db2_file, create=True,
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

        # restore paths
        os.environ["PATH"] = self.old_path
        os.environ["HOME"] = self.old_home

        def _delete_temporary_dirs():
            # XXX should not access "private" attrs
            for f in [self._soledad.local_db_path,
                    self._soledad.secrets.secrets_path]:
                if os.path.isfile(f):
                    os.unlink(f)
            # The following snippet comes from BaseLeapTest.setUpClass, but we
            # repeat it here because twisted.trial does not work with
            # setUpClass/tearDownClass.
            soledad_assert(
                self.tempdir.startswith('/tmp/leap_tests-'),
                "beware! tried to remove a dir which does not "
                "live in temporal folder!")
            shutil.rmtree(self.tempdir)

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

        return Soledad(
            user,
            passphrase,
            secrets_path=os.path.join(
                self.tempdir, prefix, secrets_path),
            local_db_path=os.path.join(
                self.tempdir, prefix, local_db_path),
            server_url=server_url,  # Soledad will fail if not given an url.
            cert_file=cert_file,
            defer_encryption=self.defer_sync_encryption,
            shared_db=MockSharedDB(),
            auth_token=auth_token)

    def assertGetEncryptedDoc(
            self, db, doc_id, doc_rev, content, has_conflicts):
        """
        Assert that the document in the database looks correct.
        """
        exp_doc = self.make_document(doc_id, doc_rev, content,
                                     has_conflicts=has_conflicts)
        doc = db.get_doc(doc_id)

        if ENC_SCHEME_KEY in doc.content:
            # XXX check for SYM_KEY too
            key = self._soledad._crypto.doc_passphrase(doc.doc_id)
            secret = self._soledad._crypto.secret
            decrypted = decrypt_doc_dict(
                doc.content, doc.doc_id, doc.rev,
                key, secret)
            doc.set_json(decrypted)
        self.assertEqual(exp_doc.doc_id, doc.doc_id)
        self.assertEqual(exp_doc.rev, doc.rev)
        self.assertEqual(exp_doc.has_conflicts, doc.has_conflicts)
        self.assertEqual(exp_doc.content, doc.content)


#-----------------------------------------------------------------------------
# A wrapper for running couchdb locally.
#-----------------------------------------------------------------------------

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

        shutil.copy('/etc/couchdb/default.ini', self.tempdir)
        defaultConfPath = os.path.join(self.tempdir, 'default.ini')

        confPath = os.path.join(self.tempdir, 'test.ini')
        handle = open(confPath, 'w')
        handle.write(conf)
        handle.close()

        # create the dirs from the template
        mkdir_p(os.path.join(self.tempdir, 'lib'))
        mkdir_p(os.path.join(self.tempdir, 'log'))
        args = ['/usr/bin/couchdb', '-n', '-a', defaultConfPath, '-a', confPath]
        null = open('/dev/null', 'w')

        self.process = subprocess.Popen(
            args, env=None, stdout=null.fileno(), stderr=null.fileno(),
            close_fds=True)
        # find port
        logPath = os.path.join(self.tempdir, 'log', 'couch.log')
        while not os.path.exists(logPath):
            if self.process.poll() is not None:
                got_stdout, got_stderr = "", ""
                if self.process.stdout is not None:
                    got_stdout = self.process.stdout.read()

                if self.process.stderr is not None:
                    got_stderr = self.process.stderr.read()
                raise Exception("""
couchdb exited with code %d.
stdout:
%s
stderr:
%s""" % (
                    self.process.returncode, got_stdout, got_stderr))
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


class CouchDBTestCase(unittest.TestCase, MockedSharedDBTest):
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

    def tearDown(self):
        """
        Stop CouchDB instance for test.
        """
        self.wrapper.stop()

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

    def setUp(self):
        CouchDBTestCase.setUp(self)
        BaseSoledadTest.setUp(self)
        main_test_class = getattr(self, 'main_test_class', None)
        if main_test_class is not None:
            main_test_class.setUp(self)
        self._couch_url = 'http://localhost:%d' % self.wrapper.port

    def tearDown(self):
        main_test_class = getattr(self, 'main_test_class', None)
        if main_test_class is not None:
            main_test_class.tearDown(self)
        # delete the test database
        try:
            db = CouchDatabase(self._couch_url, 'test')
            db.delete_database()
        except DatabaseDoesNotExist:
            pass
        BaseSoledadTest.tearDown(self)
        CouchDBTestCase.tearDown(self)

    def make_app(self):
        couch_url = urljoin(
            'http://localhost:' + str(self.wrapper.port), 'tests')
        self.request_state = CouchServerStateForTests(couch_url)
        return self.make_app_with_state(self.request_state)
