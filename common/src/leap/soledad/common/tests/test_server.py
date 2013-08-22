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
from leap.soledad.common.tests.test_target import (
    make_token_soledad_app,
    make_leap_document_for_test,
    token_leap_sync_target,
)
from leap.soledad.client import (
    Soledad,
    target,
)
from leap.soledad.server import SoledadApp
from leap.soledad.server.auth import URLToAuthorization


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
        authmap = URLToAuthorization(
            uuid, SoledadApp.SHARED_DB_NAME, SoledadApp.USER_DB_PREFIX)
        dbname = authmap._uuid_dbname(uuid)
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
        authmap = URLToAuthorization(
            uuid, SoledadApp.SHARED_DB_NAME, SoledadApp.USER_DB_PREFIX)
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

    def _soledad_instance(self, user='user-uuid', passphrase='123',
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
        self.request_state = CouchServerState(self._couch_url)
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
        # sync with server
        sol1._server_url = self.getURL()
        sol1.sync()
        # assert doc was sent to couch db
        db = CouchDatabase(
            self._couch_url,
            # the name of the user database is "user-<uuid>".
            'user-user-uuid',
        )
        _, doclist = db.get_all_docs()
        self.assertEqual(1, len(doclist))
        couchdoc = doclist[0]
        # assert document structure in couch server
        self.assertEqual(doc1.doc_id, couchdoc.doc_id)
        self.assertEqual(doc1.rev, couchdoc.rev)
        self.assertEqual(6, len(couchdoc.content))
        self.assertTrue(target.ENC_JSON_KEY in couchdoc.content)
        self.assertTrue(target.ENC_SCHEME_KEY in couchdoc.content)
        self.assertTrue(target.ENC_METHOD_KEY in couchdoc.content)
        self.assertTrue(target.ENC_IV_KEY in couchdoc.content)
        self.assertTrue(target.MAC_KEY in couchdoc.content)
        self.assertTrue(target.MAC_METHOD_KEY in couchdoc.content)
        # instantiate soledad with empty db, but with same secrets path
        sol2 = self._soledad_instance(prefix='x', auth_token='auth-token')
        _, doclist = sol2.get_all_docs()
        self.assertEqual([], doclist)
        sol2._secrets_path = sol1.secrets_path
        sol2._load_secrets()
        sol2._set_secret_id(sol1._secret_id)
        # sync the new instance
        sol2._server_url = self.getURL()
        sol2.sync()
        _, doclist = sol2.get_all_docs()
        self.assertEqual(1, len(doclist))
        doc2 = doclist[0]
        # assert incoming doc is equal to the first sent doc
        self.assertEqual(doc1, doc2)
