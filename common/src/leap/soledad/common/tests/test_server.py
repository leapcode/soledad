# -*- coding: utf-8 -*-
# test_server.py
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
Tests for server-related functionality.
"""
import os
import tempfile
import simplejson as json
import mock
import time
import binascii

from urlparse import urljoin

from leap.common.testing.basetest import BaseLeapTest
from leap.soledad.common.couch import (
    CouchServerState,
    CouchDatabase,
)
from leap.soledad.common.tests.u1db_tests import (
    TestCaseWithServer,
    simple_doc,
)
from leap.soledad.common.tests.test_couch import CouchDBTestCase
from leap.soledad.common.tests.test_target_soledad import (
    make_token_soledad_app,
    make_leap_document_for_test,
)
from leap.soledad.common.tests.test_sync_target import token_leap_sync_target
from leap.soledad.client import Soledad, crypto
from leap.soledad.server import LockResource
from leap.soledad.server.auth import URLToAuthorization


# monkey path CouchServerState so it can ensure databases.

def _couch_ensure_database(self, dbname):
    db = CouchDatabase.open_database(
        self._couch_url + '/' + dbname,
        create=True,
        ensure_ddocs=True)
    return db, db._replica_uid

CouchServerState.ensure_database = _couch_ensure_database


class ServerAuthorizationTestCase(BaseLeapTest):
    """
    Tests related to Soledad server authorization.
    """

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def _make_environ(self, path_info, request_method):
        return {
            'PATH_INFO': path_info,
            'REQUEST_METHOD': request_method,
        }

    def test_verify_action_with_correct_dbnames(self):
        """
        Test encrypting and decrypting documents.

        The following table lists the authorized actions among all possible
        u1db remote actions:

            URL path                      | Authorized actions
            --------------------------------------------------
            /                             | GET
            /shared-db                    | GET
            /shared-db/docs               | -
            /shared-db/doc/{id}           | GET, PUT, DELETE
            /shared-db/sync-from/{source} | -
            /user-db                      | GET, PUT, DELETE
            /user-db/docs                 | -
            /user-db/doc/{id}             | -
            /user-db/sync-from/{source}   | GET, PUT, POST
        """
        uuid = 'myuuid'
        authmap = URLToAuthorization(uuid,)
        dbname = authmap._user_db_name
        # test global auth
        self.assertTrue(
            authmap.is_authorized(self._make_environ('/', 'GET')))
        # test shared-db database resource auth
        self.assertTrue(
            authmap.is_authorized(
                self._make_environ('/shared', 'GET')))
        self.assertFalse(
            authmap.is_authorized(
                self._make_environ('/shared', 'PUT')))
        self.assertFalse(
            authmap.is_authorized(
                self._make_environ('/shared', 'DELETE')))
        self.assertFalse(
            authmap.is_authorized(
                self._make_environ('/shared', 'POST')))
        # test shared-db docs resource auth
        self.assertFalse(
            authmap.is_authorized(
                self._make_environ('/shared/docs', 'GET')))
        self.assertFalse(
            authmap.is_authorized(
                self._make_environ('/shared/docs', 'PUT')))
        self.assertFalse(
            authmap.is_authorized(
                self._make_environ('/shared/docs', 'DELETE')))
        self.assertFalse(
            authmap.is_authorized(
                self._make_environ('/shared/docs', 'POST')))
        # test shared-db doc resource auth
        self.assertTrue(
            authmap.is_authorized(
                self._make_environ('/shared/doc/x', 'GET')))
        self.assertTrue(
            authmap.is_authorized(
                self._make_environ('/shared/doc/x', 'PUT')))
        self.assertTrue(
            authmap.is_authorized(
                self._make_environ('/shared/doc/x', 'DELETE')))
        self.assertFalse(
            authmap.is_authorized(
                self._make_environ('/shared/doc/x', 'POST')))
        # test shared-db sync resource auth
        self.assertFalse(
            authmap.is_authorized(
                self._make_environ('/shared/sync-from/x', 'GET')))
        self.assertFalse(
            authmap.is_authorized(
                self._make_environ('/shared/sync-from/x', 'PUT')))
        self.assertFalse(
            authmap.is_authorized(
                self._make_environ('/shared/sync-from/x', 'DELETE')))
        self.assertFalse(
            authmap.is_authorized(
                self._make_environ('/shared/sync-from/x', 'POST')))
        # test user-db database resource auth
        self.assertTrue(
            authmap.is_authorized(
                self._make_environ('/%s' % dbname, 'GET')))
        self.assertTrue(
            authmap.is_authorized(
                self._make_environ('/%s' % dbname, 'PUT')))
        self.assertTrue(
            authmap.is_authorized(
                self._make_environ('/%s' % dbname, 'DELETE')))
        self.assertFalse(
            authmap.is_authorized(
                self._make_environ('/%s' % dbname, 'POST')))
        # test user-db docs resource auth
        self.assertFalse(
            authmap.is_authorized(
                self._make_environ('/%s/docs' % dbname, 'GET')))
        self.assertFalse(
            authmap.is_authorized(
                self._make_environ('/%s/docs' % dbname, 'PUT')))
        self.assertFalse(
            authmap.is_authorized(
                self._make_environ('/%s/docs' % dbname, 'DELETE')))
        self.assertFalse(
            authmap.is_authorized(
                self._make_environ('/%s/docs' % dbname, 'POST')))
        # test user-db doc resource auth
        self.assertFalse(
            authmap.is_authorized(
                self._make_environ('/%s/doc/x' % dbname, 'GET')))
        self.assertFalse(
            authmap.is_authorized(
                self._make_environ('/%s/doc/x' % dbname, 'PUT')))
        self.assertFalse(
            authmap.is_authorized(
                self._make_environ('/%s/doc/x' % dbname, 'DELETE')))
        self.assertFalse(
            authmap.is_authorized(
                self._make_environ('/%s/doc/x' % dbname, 'POST')))
        # test user-db sync resource auth
        self.assertTrue(
            authmap.is_authorized(
                self._make_environ('/%s/sync-from/x' % dbname, 'GET')))
        self.assertTrue(
            authmap.is_authorized(
                self._make_environ('/%s/sync-from/x' % dbname, 'PUT')))
        self.assertFalse(
            authmap.is_authorized(
                self._make_environ('/%s/sync-from/x' % dbname, 'DELETE')))
        self.assertTrue(
            authmap.is_authorized(
                self._make_environ('/%s/sync-from/x' % dbname, 'POST')))

    def test_verify_action_with_wrong_dbnames(self):
        """
        Test if authorization fails for a wrong dbname.
        """
        uuid = 'myuuid'
        authmap = URLToAuthorization(uuid)
        dbname = 'somedb'
        # test wrong-db database resource auth
        self.assertFalse(
            authmap.is_authorized(
                self._make_environ('/%s' % dbname, 'GET')))
        self.assertFalse(
            authmap.is_authorized(
                self._make_environ('/%s' % dbname, 'PUT')))
        self.assertFalse(
            authmap.is_authorized(
                self._make_environ('/%s' % dbname, 'DELETE')))
        self.assertFalse(
            authmap.is_authorized(
                self._make_environ('/%s' % dbname, 'POST')))
        # test wrong-db docs resource auth
        self.assertFalse(
            authmap.is_authorized(
                self._make_environ('/%s/docs' % dbname, 'GET')))
        self.assertFalse(
            authmap.is_authorized(
                self._make_environ('/%s/docs' % dbname, 'PUT')))
        self.assertFalse(
            authmap.is_authorized(
                self._make_environ('/%s/docs' % dbname, 'DELETE')))
        self.assertFalse(
            authmap.is_authorized(
                self._make_environ('/%s/docs' % dbname, 'POST')))
        # test wrong-db doc resource auth
        self.assertFalse(
            authmap.is_authorized(
                self._make_environ('/%s/doc/x' % dbname, 'GET')))
        self.assertFalse(
            authmap.is_authorized(
                self._make_environ('/%s/doc/x' % dbname, 'PUT')))
        self.assertFalse(
            authmap.is_authorized(
                self._make_environ('/%s/doc/x' % dbname, 'DELETE')))
        self.assertFalse(
            authmap.is_authorized(
                self._make_environ('/%s/doc/x' % dbname, 'POST')))
        # test wrong-db sync resource auth
        self.assertFalse(
            authmap.is_authorized(
                self._make_environ('/%s/sync-from/x' % dbname, 'GET')))
        self.assertFalse(
            authmap.is_authorized(
                self._make_environ('/%s/sync-from/x' % dbname, 'PUT')))
        self.assertFalse(
            authmap.is_authorized(
                self._make_environ('/%s/sync-from/x' % dbname, 'DELETE')))
        self.assertFalse(
            authmap.is_authorized(
                self._make_environ('/%s/sync-from/x' % dbname, 'POST')))


class EncryptedSyncTestCase(
        CouchDBTestCase, TestCaseWithServer):
    """
    Tests for encrypted sync using Soledad server backed by a couch database.
    """

    @staticmethod
    def make_app_with_state(state):
        return make_token_soledad_app(state)

    make_document_for_test = make_leap_document_for_test

    sync_target = token_leap_sync_target

    def _soledad_instance(self, user='user-uuid', passphrase=u'123',
                          prefix='',
                          secrets_path=Soledad.STORAGE_SECRETS_FILE_NAME,
                          local_db_path='soledad.u1db', server_url='',
                          cert_file=None, auth_token=None, secret_id=None):
        """
        Instantiate Soledad.
        """

        # this callback ensures we save a document which is sent to the shared
        # db.
        def _put_doc_side_effect(doc):
            self._doc_put = doc

        # we need a mocked shared db or else Soledad will try to access the
        # network to find if there are uploaded secrets.
        class MockSharedDB(object):

            get_doc = mock.Mock(return_value=None)
            put_doc = mock.Mock(side_effect=_put_doc_side_effect)
            lock = mock.Mock(return_value=('atoken', 300))
            unlock = mock.Mock()
            close = mock.Mock()

            def __call__(self):
                return self

        Soledad._shared_db = MockSharedDB()
        return Soledad(
            user,
            passphrase,
            secrets_path=os.path.join(self.tempdir, prefix, secrets_path),
            local_db_path=os.path.join(
                self.tempdir, prefix, local_db_path),
            server_url=server_url,
            cert_file=cert_file,
            auth_token=auth_token,
            secret_id=secret_id)

    def make_app(self):
        self.request_state = CouchServerState(self._couch_url, 'shared',
                                              'tokens')
        return self.make_app_with_state(self.request_state)

    def setUp(self):
        TestCaseWithServer.setUp(self)
        CouchDBTestCase.setUp(self)
        self.tempdir = tempfile.mkdtemp(prefix="leap_tests-")
        self._couch_url = 'http://localhost:' + str(self.wrapper.port)

    def tearDown(self):
        CouchDBTestCase.tearDown(self)
        TestCaseWithServer.tearDown(self)

    def test_encrypted_sym_sync(self):
        """
        Test the complete syncing chain between two soledad dbs using a
        Soledad server backed by a couch database.
        """
        self.startServer()
        # instantiate soledad and create a document
        sol1 = self._soledad_instance(
            # token is verified in test_target.make_token_soledad_app
            auth_token='auth-token'
        )
        _, doclist = sol1.get_all_docs()
        self.assertEqual([], doclist)
        doc1 = sol1.create_doc(json.loads(simple_doc))
        # ensure remote db exists before syncing
        db = CouchDatabase.open_database(
            urljoin(self._couch_url, 'user-user-uuid'),
            create=True,
            ensure_ddocs=True)
        # sync with server
        sol1._server_url = self.getURL()
        sol1.sync()
        # assert doc was sent to couch db
        _, doclist = db.get_all_docs()
        self.assertEqual(1, len(doclist))
        couchdoc = doclist[0]
        # assert document structure in couch server
        self.assertEqual(doc1.doc_id, couchdoc.doc_id)
        self.assertEqual(doc1.rev, couchdoc.rev)
        self.assertEqual(6, len(couchdoc.content))
        self.assertTrue(crypto.ENC_JSON_KEY in couchdoc.content)
        self.assertTrue(crypto.ENC_SCHEME_KEY in couchdoc.content)
        self.assertTrue(crypto.ENC_METHOD_KEY in couchdoc.content)
        self.assertTrue(crypto.ENC_IV_KEY in couchdoc.content)
        self.assertTrue(crypto.MAC_KEY in couchdoc.content)
        self.assertTrue(crypto.MAC_METHOD_KEY in couchdoc.content)
        # instantiate soledad with empty db, but with same secrets path
        sol2 = self._soledad_instance(prefix='x', auth_token='auth-token')
        _, doclist = sol2.get_all_docs()
        self.assertEqual([], doclist)
        sol2.secrets_path = sol1.secrets_path
        sol2.secrets._load_secrets()
        sol2.set_secret_id(sol1.secret_id)
        # sync the new instance
        sol2._server_url = self.getURL()
        sol2.sync()
        _, doclist = sol2.get_all_docs()
        self.assertEqual(1, len(doclist))
        doc2 = doclist[0]
        # assert incoming doc is equal to the first sent doc
        self.assertEqual(doc1, doc2)
        db.delete_database()
        db.close()
        sol1.close()
        sol2.close()

    def test_encrypted_sym_sync_with_unicode_passphrase(self):
        """
        Test the complete syncing chain between two soledad dbs using a
        Soledad server backed by a couch database, using an unicode
        passphrase.
        """
        self.startServer()
        # instantiate soledad and create a document
        sol1 = self._soledad_instance(
            # token is verified in test_target.make_token_soledad_app
            auth_token='auth-token',
            passphrase=u'ãáàäéàëíìïóòöõúùüñç',
        )
        _, doclist = sol1.get_all_docs()
        self.assertEqual([], doclist)
        doc1 = sol1.create_doc(json.loads(simple_doc))
        # ensure remote db exists before syncing
        db = CouchDatabase.open_database(
            urljoin(self._couch_url, 'user-user-uuid'),
            create=True,
            ensure_ddocs=True)
        # sync with server
        sol1._server_url = self.getURL()
        sol1.sync()
        # assert doc was sent to couch db
        _, doclist = db.get_all_docs()
        self.assertEqual(1, len(doclist))
        couchdoc = doclist[0]
        # assert document structure in couch server
        self.assertEqual(doc1.doc_id, couchdoc.doc_id)
        self.assertEqual(doc1.rev, couchdoc.rev)
        self.assertEqual(6, len(couchdoc.content))
        self.assertTrue(crypto.ENC_JSON_KEY in couchdoc.content)
        self.assertTrue(crypto.ENC_SCHEME_KEY in couchdoc.content)
        self.assertTrue(crypto.ENC_METHOD_KEY in couchdoc.content)
        self.assertTrue(crypto.ENC_IV_KEY in couchdoc.content)
        self.assertTrue(crypto.MAC_KEY in couchdoc.content)
        self.assertTrue(crypto.MAC_METHOD_KEY in couchdoc.content)
        # instantiate soledad with empty db, but with same secrets path
        sol2 = self._soledad_instance(
            prefix='x',
            auth_token='auth-token',
            passphrase=u'ãáàäéàëíìïóòöõúùüñç',
        )
        _, doclist = sol2.get_all_docs()
        self.assertEqual([], doclist)
        sol2.secrets_path = sol1.secrets_path
        sol2.secrets._load_secrets()
        sol2.set_secret_id(sol1.secret_id)
        # sync the new instance
        sol2._server_url = self.getURL()
        sol2.sync()
        _, doclist = sol2.get_all_docs()
        self.assertEqual(1, len(doclist))
        doc2 = doclist[0]
        # assert incoming doc is equal to the first sent doc
        self.assertEqual(doc1, doc2)
        db.delete_database()
        db.close()
        sol1.close()
        sol2.close()

    def test_sync_very_large_files(self):
        """
        Test if Soledad can sync very large files.
        """
        # define the size of the "very large file"
        length = 100*(10**6)  # 100 MB
        self.startServer()
        # instantiate soledad and create a document
        sol1 = self._soledad_instance(
            # token is verified in test_target.make_token_soledad_app
            auth_token='auth-token'
        )
        _, doclist = sol1.get_all_docs()
        self.assertEqual([], doclist)
        content = binascii.hexlify(os.urandom(length/2))  # len() == length
        doc1 = sol1.create_doc({'data': content})
        # ensure remote db exists before syncing
        db = CouchDatabase.open_database(
            urljoin(self._couch_url, 'user-user-uuid'),
            create=True,
            ensure_ddocs=True)
        # sync with server
        sol1._server_url = self.getURL()
        sol1.sync()
        # instantiate soledad with empty db, but with same secrets path
        sol2 = self._soledad_instance(prefix='x', auth_token='auth-token')
        _, doclist = sol2.get_all_docs()
        self.assertEqual([], doclist)
        sol2.secrets_path = sol1.secrets_path
        sol2.secrets._load_secrets()
        sol2.set_secret_id(sol1.secret_id)
        # sync the new instance
        sol2._server_url = self.getURL()
        sol2.sync()
        _, doclist = sol2.get_all_docs()
        self.assertEqual(1, len(doclist))
        doc2 = doclist[0]
        # assert incoming doc is equal to the first sent doc
        self.assertEqual(doc1, doc2)
        # delete remote database
        db.delete_database()
        db.close()
        sol1.close()
        sol2.close()

    def test_sync_many_small_files(self):
        """
        Test if Soledad can sync many smallfiles.
        """
        number_of_docs = 100
        self.startServer()
        # instantiate soledad and create a document
        sol1 = self._soledad_instance(
            # token is verified in test_target.make_token_soledad_app
            auth_token='auth-token'
        )
        _, doclist = sol1.get_all_docs()
        self.assertEqual([], doclist)
        # create many small files
        for i in range(0, number_of_docs):
            sol1.create_doc(json.loads(simple_doc))
        # ensure remote db exists before syncing
        db = CouchDatabase.open_database(
            urljoin(self._couch_url, 'user-user-uuid'),
            create=True,
            ensure_ddocs=True)
        # sync with server
        sol1._server_url = self.getURL()
        sol1.sync()
        # instantiate soledad with empty db, but with same secrets path
        sol2 = self._soledad_instance(prefix='x', auth_token='auth-token')
        _, doclist = sol2.get_all_docs()
        self.assertEqual([], doclist)
        sol2.secrets_path = sol1.secrets_path
        sol2.secrets._load_secrets()
        sol2.set_secret_id(sol1.secret_id)
        # sync the new instance
        sol2._server_url = self.getURL()
        sol2.sync()
        _, doclist = sol2.get_all_docs()
        self.assertEqual(number_of_docs, len(doclist))
        # assert incoming docs are equal to sent docs
        for doc in doclist:
            self.assertEqual(sol1.get_doc(doc.doc_id), doc)
        # delete remote database
        db.delete_database()
        db.close()
        sol1.close()
        sol2.close()


class LockResourceTestCase(
        CouchDBTestCase, TestCaseWithServer):
    """
    Tests for use of PUT and DELETE on lock resource.
    """

    @staticmethod
    def make_app_with_state(state):
        return make_token_soledad_app(state)

    make_document_for_test = make_leap_document_for_test

    sync_target = token_leap_sync_target

    def setUp(self):
        TestCaseWithServer.setUp(self)
        CouchDBTestCase.setUp(self)
        self.tempdir = tempfile.mkdtemp(prefix="leap_tests-")
        self._couch_url = 'http://localhost:' + str(self.wrapper.port)
        # create the databases
        CouchDatabase.open_database(
            urljoin(self._couch_url, 'shared'),
            create=True,
            ensure_ddocs=True)
        CouchDatabase.open_database(
            urljoin(self._couch_url, 'tokens'),
            create=True,
            ensure_ddocs=True)
        self._state = CouchServerState(
            self._couch_url, 'shared', 'tokens')

    def tearDown(self):
        CouchDBTestCase.tearDown(self)
        TestCaseWithServer.tearDown(self)
        # delete remote database
        db = CouchDatabase.open_database(
            urljoin(self._couch_url, 'shared'),
            create=True,
            ensure_ddocs=True)
        db.delete_database()

    def test__try_obtain_filesystem_lock(self):
        responder = mock.Mock()
        lr = LockResource('uuid', self._state, responder)
        self.assertFalse(lr._lock.locked)
        self.assertTrue(lr._try_obtain_filesystem_lock())
        self.assertTrue(lr._lock.locked)
        lr._try_release_filesystem_lock()

    def test__try_release_filesystem_lock(self):
        responder = mock.Mock()
        lr = LockResource('uuid', self._state, responder)
        lr._try_obtain_filesystem_lock()
        self.assertTrue(lr._lock.locked)
        lr._try_release_filesystem_lock()
        self.assertFalse(lr._lock.locked)

    def test_put(self):
        responder = mock.Mock()
        lr = LockResource('uuid', self._state, responder)
        # lock!
        lr.put({}, None)
        # assert lock document was correctly written
        lock_doc = lr._shared_db.get_doc('lock-uuid')
        self.assertIsNotNone(lock_doc)
        self.assertTrue(LockResource.TIMESTAMP_KEY in lock_doc.content)
        self.assertTrue(LockResource.LOCK_TOKEN_KEY in lock_doc.content)
        timestamp = lock_doc.content[LockResource.TIMESTAMP_KEY]
        token = lock_doc.content[LockResource.LOCK_TOKEN_KEY]
        self.assertTrue(timestamp < time.time())
        self.assertTrue(time.time() < timestamp + LockResource.TIMEOUT)
        # assert response to user
        responder.send_response_json.assert_called_with(
            201, token=token,
            timeout=LockResource.TIMEOUT)

    def test_delete(self):
        responder = mock.Mock()
        lr = LockResource('uuid', self._state, responder)
        # lock!
        lr.put({}, None)
        lock_doc = lr._shared_db.get_doc('lock-uuid')
        token = lock_doc.content[LockResource.LOCK_TOKEN_KEY]
        # unlock!
        lr.delete({'token': token}, None)
        self.assertFalse(lr._lock.locked)
        self.assertIsNone(lr._shared_db.get_doc('lock-uuid'))
        responder.send_response_json.assert_called_with(200)

    def test_put_while_locked_fails(self):
        responder = mock.Mock()
        lr = LockResource('uuid', self._state, responder)
        # lock!
        lr.put({}, None)
        # try to lock again!
        lr.put({}, None)
        self.assertEqual(
            len(responder.send_response_json.call_args), 2)
        self.assertEqual(
            responder.send_response_json.call_args[0], (403,))
        self.assertEqual(
            len(responder.send_response_json.call_args[1]), 2)
        self.assertTrue(
            'remaining' in responder.send_response_json.call_args[1])
        self.assertTrue(
            responder.send_response_json.call_args[1]['remaining'] > 0)

    def test_unlock_unexisting_lock_fails(self):
        responder = mock.Mock()
        lr = LockResource('uuid', self._state, responder)
        # unlock!
        lr.delete({'token': 'anything'}, None)
        responder.send_response_json.assert_called_with(
            404, error='lock not found')

    def test_unlock_with_wrong_token_fails(self):
        responder = mock.Mock()
        lr = LockResource('uuid', self._state, responder)
        # lock!
        lr.put({}, None)
        # unlock!
        lr.delete({'token': 'wrongtoken'}, None)
        self.assertIsNotNone(lr._shared_db.get_doc('lock-uuid'))
        responder.send_response_json.assert_called_with(
            401, error='unlock unauthorized')
