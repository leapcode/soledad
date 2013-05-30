# -*- coding: utf-8 -*-
# test_leap_backend.py
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
Test Leap backend bits.
"""

import u1db
import os
import ssl
import simplejson as json
import cStringIO


from u1db.sync import Synchronizer
from u1db.remote import (
    http_client,
    http_database,
    http_target,
)
from routes.mapper import Mapper

from leap import soledad
from leap.soledad.backends import leap_backend
from leap.soledad.server import (
    SoledadApp,
    SoledadAuthMiddleware,
)
from leap.soledad import auth


from leap.soledad.tests import u1db_tests as tests
from leap.soledad.tests import BaseSoledadTest
from leap.soledad.tests.u1db_tests import test_backends
from leap.soledad.tests.u1db_tests import test_http_database
from leap.soledad.tests.u1db_tests import test_http_client
from leap.soledad.tests.u1db_tests import test_document
from leap.soledad.tests.u1db_tests import test_remote_sync_target
from leap.soledad.tests.u1db_tests import test_https
from leap.soledad.tests.u1db_tests import test_sync


#-----------------------------------------------------------------------------
# The following tests come from `u1db.tests.test_backends`.
#-----------------------------------------------------------------------------

def make_leap_document_for_test(test, doc_id, rev, content,
                                has_conflicts=False):
    return leap_backend.LeapDocument(
        doc_id, rev, content, has_conflicts=has_conflicts)


def make_soledad_app(state):
    return SoledadApp(state)


def make_token_soledad_app(state):
    app = SoledadApp(state)

    def verify_token(environ, uuid, token):
        if uuid == 'user-uuid' and token == 'auth-token':
            return True
        return False

    # we test for action authorization in leap.soledad.tests.test_server
    def verify_action(environ, uuid):
        return True

    application = SoledadAuthMiddleware(app)
    application.verify_token = verify_token
    application.verify_action = verify_action
    return application


LEAP_SCENARIOS = [
    ('http', {
        'make_database_for_test': test_backends.make_http_database_for_test,
        'copy_database_for_test': test_backends.copy_http_database_for_test,
        'make_document_for_test': make_leap_document_for_test,
        'make_app_with_state': make_soledad_app}),
]


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


class LeapTests(test_backends.AllDatabaseTests, BaseSoledadTest):

    scenarios = LEAP_SCENARIOS + [
        ('token_http', {'make_database_for_test':
                        make_token_http_database_for_test,
                        'copy_database_for_test':
                        copy_token_http_database_for_test,
                        'make_document_for_test': make_leap_document_for_test,
                        'make_app_with_state': make_token_soledad_app,
                        })
    ]


#-----------------------------------------------------------------------------
# The following tests come from `u1db.tests.test_http_client`.
#-----------------------------------------------------------------------------

class TestLeapClientBase(test_http_client.TestHTTPClientBase):
    """
    This class should be used to test Token auth.
    """

    def getClientWithToken(self, **kwds):
        self.startServer()

        class _HTTPClientWithToken(
                http_client.HTTPClientBase, auth.TokenBasedAuth):

            def set_token_credentials(self, uuid, token):
                auth.TokenBasedAuth.set_token_credentials(self, uuid, token)

            def _sign_request(self, method, url_query, params):
                return auth.TokenBasedAuth._sign_request(
                    self, method, url_query, params)

        return _HTTPClientWithToken(self.getURL('dbase'), **kwds)

    def test_oauth(self):
        """
        Suppress oauth test (we test for token auth here).
        """
        pass

    def test_oauth_ctr_creds(self):
        """
        Suppress oauth test (we test for token auth here).
        """
        pass

    def test_oauth_Unauthorized(self):
        """
        Suppress oauth test (we test for token auth here).
        """
        pass

    def app(self, environ, start_response):
        res = test_http_client.TestHTTPClientBase.app(
            self, environ, start_response)
        if res is not None:
            return res
        # mime solead application here.
        if '/token' in environ['PATH_INFO']:
            auth = environ.get(SoledadAuthMiddleware.HTTP_AUTH_KEY)
            if not auth:
                start_response("401 Unauthorized",
                               [('Content-Type', 'application/json')])
                return [json.dumps({"error": "unauthorized",
                                    "message": e.message})]
            scheme, encoded = auth.split(None, 1)
            if scheme.lower() != 'token':
                start_response("401 Unauthorized",
                               [('Content-Type', 'application/json')])
                return [json.dumps({"error": "unauthorized",
                                    "message": e.message})]
            uuid, token = encoded.decode('base64').split(':', 1)
            if uuid != 'user-uuid' and token != 'auth-token':
                return unauth_err("Incorrect address or token.")
            start_response("200 OK", [('Content-Type', 'application/json')])
            return [json.dumps([environ['PATH_INFO'], uuid, token])]

    def test_token(self):
        """
        Test if token is sent correctly.
        """
        cli = self.getClientWithToken()
        cli.set_token_credentials('user-uuid', 'auth-token')
        res, headers = cli._request('GET', ['doc', 'token'])
        self.assertEqual(
            ['/dbase/doc/token', 'user-uuid', 'auth-token'], json.loads(res))

    def test_token_ctr_creds(self):
        cli = self.getClientWithToken(creds={'token': {
            'uuid': 'user-uuid',
            'token': 'auth-token',
        }})
        res, headers = cli._request('GET', ['doc', 'token'])
        self.assertEqual(
            ['/dbase/doc/token', 'user-uuid', 'auth-token'], json.loads(res))


#-----------------------------------------------------------------------------
# The following tests come from `u1db.tests.test_document`.
#-----------------------------------------------------------------------------

class TestLeapDocument(test_document.TestDocument, BaseSoledadTest):

    scenarios = ([(
        'leap', {'make_document_for_test': make_leap_document_for_test})])


class TestLeapPyDocument(test_document.TestPyDocument, BaseSoledadTest):

    scenarios = ([(
        'leap', {'make_document_for_test': make_leap_document_for_test})])


#-----------------------------------------------------------------------------
# The following tests come from `u1db.tests.test_remote_sync_target`.
#-----------------------------------------------------------------------------

class TestLeapSyncTargetBasics(
        test_remote_sync_target.TestHTTPSyncTargetBasics):
    """
    Some tests had to be copied to this class so we can instantiate our own
    target.
    """

    def test_parse_url(self):
        remote_target = leap_backend.LeapSyncTarget('http://127.0.0.1:12345/')
        self.assertEqual('http', remote_target._url.scheme)
        self.assertEqual('127.0.0.1', remote_target._url.hostname)
        self.assertEqual(12345, remote_target._url.port)
        self.assertEqual('/', remote_target._url.path)


class TestLeapParsingSyncStream(
        test_remote_sync_target.TestParsingSyncStream,
        BaseSoledadTest):
    """
    Some tests had to be copied to this class so we can instantiate our own
    target.
    """

    def setUp(self):
        test_remote_sync_target.TestParsingSyncStream.setUp(self)
        BaseSoledadTest.setUp(self)

    def tearDown(self):
        test_remote_sync_target.TestParsingSyncStream.tearDown(self)
        BaseSoledadTest.tearDown(self)

    def test_extra_comma(self):
        """
        Test adapted to use encrypted content.
        """
        doc = leap_backend.LeapDocument('i', rev='r')
        doc.content = {}
        enc_json = leap_backend.encrypt_doc(self._soledad._crypto, doc)
        tgt = leap_backend.LeapSyncTarget(
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
        tgt = leap_backend.LeapSyncTarget("http://foo/foo")

        self.assertRaises(u1db.errors.BrokenSyncStream,
                          tgt._parse_sync_stream, "{}\r\n]", None)

        self.assertRaises(u1db.errors.BrokenSyncStream,
                          tgt._parse_sync_stream, "\r\n{}\r\n]", None)

        self.assertRaises(u1db.errors.BrokenSyncStream,
                          tgt._parse_sync_stream, "", None)

    def test_wrong_end(self):
        tgt = leap_backend.LeapSyncTarget("http://foo/foo")

        self.assertRaises(u1db.errors.BrokenSyncStream,
                          tgt._parse_sync_stream, "[\r\n{}", None)

        self.assertRaises(u1db.errors.BrokenSyncStream,
                          tgt._parse_sync_stream, "[\r\n", None)

    def test_missing_comma(self):
        tgt = leap_backend.LeapSyncTarget("http://foo/foo")

        self.assertRaises(u1db.errors.BrokenSyncStream,
                          tgt._parse_sync_stream,
                          '[\r\n{}\r\n{"id": "i", "rev": "r", '
                          '"content": "c", "gen": 3}\r\n]', None)

    def test_no_entries(self):
        tgt = leap_backend.LeapSyncTarget("http://foo/foo")

        self.assertRaises(u1db.errors.BrokenSyncStream,
                          tgt._parse_sync_stream, "[\r\n]", None)

    def test_error_in_stream(self):
        tgt = leap_backend.LeapSyncTarget("http://foo/foo")

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

def leap_sync_target(test, path):
    return leap_backend.LeapSyncTarget(
        test.getURL(path), crypto=test._soledad._crypto)


def token_leap_sync_target(test, path):
    st = leap_sync_target(test, path)
    st.set_token_credentials('user-uuid', 'auth-token')
    return st


class TestLeapSyncTarget(
        test_remote_sync_target.TestRemoteSyncTargets, BaseSoledadTest):

    scenarios = [
        ('token_soledad',
            {'make_app_with_state': make_token_soledad_app,
             'make_document_for_test': make_leap_document_for_test,
             'sync_target': token_leap_sync_target}),
    ]

    def test_sync_exchange_send(self):
        """
        Test for sync exchanging send of document.

        This test was adapted to decrypt remote content before assert.
        """
        self.startServer()
        db = self.request_state._create_database('test')
        remote_target = self.getSyncTarget('test')
        other_docs = []

        def receive_doc(doc):
            other_docs.append((doc.doc_id, doc.rev, doc.get_json()))

        doc = self.make_document('doc-here', 'replica:1', '{"value": "here"}')
        new_gen, trans_id = remote_target.sync_exchange(
            [(doc, 10, 'T-sid')], 'replica', last_known_generation=0,
            last_known_trans_id=None, return_doc_cb=receive_doc)
        self.assertEqual(1, new_gen)
        self.assertGetEncryptedDoc(
            db, 'doc-here', 'replica:1', '{"value": "here"}', False)

    def test_sync_exchange_send_failure_and_retry_scenario(self):
        """
        Test for sync exchange failure and retry.

        This test was adapted to decrypt remote content before assert.
        """

        self.startServer()

        def blackhole_getstderr(inst):
            return cStringIO.StringIO()

        self.patch(self.server.RequestHandlerClass, 'get_stderr',
                   blackhole_getstderr)
        db = self.request_state._create_database('test')
        _put_doc_if_newer = db._put_doc_if_newer
        trigger_ids = ['doc-here2']

        def bomb_put_doc_if_newer(doc, save_conflict,
                                  replica_uid=None, replica_gen=None,
                                  replica_trans_id=None):
            if doc.doc_id in trigger_ids:
                raise Exception
            return _put_doc_if_newer(doc, save_conflict=save_conflict,
                                     replica_uid=replica_uid,
                                     replica_gen=replica_gen,
                                     replica_trans_id=replica_trans_id)
        self.patch(db, '_put_doc_if_newer', bomb_put_doc_if_newer)
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
        # bounced back to us
        self.assertEqual(
            ('doc-here', 'replica:1', '{"value": "here"}', 1),
            other_changes[0][:-1])

    def test_sync_exchange_send_ensure_callback(self):
        """
        Test for sync exchange failure and retry.

        This test was adapted to decrypt remote content before assert.
        """
        self.startServer()
        remote_target = self.getSyncTarget('test')
        other_docs = []
        replica_uid_box = []

        def receive_doc(doc):
            other_docs.append((doc.doc_id, doc.rev, doc.get_json()))

        def ensure_cb(replica_uid):
            replica_uid_box.append(replica_uid)

        doc = self.make_document('doc-here', 'replica:1', '{"value": "here"}')
        new_gen, trans_id = remote_target.sync_exchange(
            [(doc, 10, 'T-sid')], 'replica', last_known_generation=0,
            last_known_trans_id=None, return_doc_cb=receive_doc,
            ensure_callback=ensure_cb)
        self.assertEqual(1, new_gen)
        db = self.request_state.open_database('test')
        self.assertEqual(1, len(replica_uid_box))
        self.assertEqual(db._replica_uid, replica_uid_box[0])
        self.assertGetEncryptedDoc(
            db, 'doc-here', 'replica:1', '{"value": "here"}', False)


#-----------------------------------------------------------------------------
# The following tests come from `u1db.tests.test_https`.
#-----------------------------------------------------------------------------

def token_leap_https_sync_target(test, host, path):
    _, port = test.server.server_address
    st = leap_backend.LeapSyncTarget(
        'https://%s:%d/%s' % (host, port, path),
        crypto=test._soledad._crypto)
    st.set_token_credentials('user-uuid', 'auth-token')
    return st


class TestLeapSyncTargetHttpsSupport(test_https.TestHttpSyncTargetHttpsSupport,
                                     BaseSoledadTest):

    scenarios = [
        ('token_soledad_https',
            {'server_def': test_https.https_server_def,
             'make_app_with_state': make_token_soledad_app,
             'make_document_for_test': make_leap_document_for_test,
             'sync_target': token_leap_https_sync_target}),
    ]

    def setUp(self):
        # the parent constructor undoes our SSL monkey patch to ensure tests
        # run smoothly with standard u1db.
        test_https.TestHttpSyncTargetHttpsSupport.setUp(self)
        # so here monkey patch again to test our functionality.
        http_client._VerifiedHTTPSConnection = soledad.VerifiedHTTPSConnection
        soledad.SOLEDAD_CERT = http_client.CA_CERTS

    def test_working(self):
        """
        Test that SSL connections work well.

        This test was adapted to patch Soledad's HTTPS connection custom class
        with the intended CA certificates.
        """
        self.startServer()
        db = self.request_state._create_database('test')
        self.patch(soledad, 'SOLEDAD_CERT', self.cacert_pem)
        remote_target = self.getSyncTarget('localhost', 'test')
        remote_target.record_sync_info('other-id', 2, 'T-id')
        self.assertEqual(
            (2, 'T-id'), db._get_replica_gen_and_trans_id('other-id'))

    def test_host_mismatch(self):
        """
        Test that SSL connections to a hostname different than the one in the
        certificate raise CertificateError.

        This test was adapted to patch Soledad's HTTPS connection custom class
        with the intended CA certificates.
        """
        self.startServer()
        self.request_state._create_database('test')
        self.patch(soledad, 'SOLEDAD_CERT', self.cacert_pem)
        remote_target = self.getSyncTarget('127.0.0.1', 'test')
        self.assertRaises(
            http_client.CertificateError, remote_target.record_sync_info,
            'other-id', 2, 'T-id')


#-----------------------------------------------------------------------------
# The following tests come from `u1db.tests.test_http_database`.
#-----------------------------------------------------------------------------

class _HTTPDatabase(http_database.HTTPDatabase, auth.TokenBasedAuth):
    """
    Wraps our token auth implementation.
    """

    def set_token_credentials(self, uuid, token):
        auth.TokenBasedAuth.set_token_credentials(self, uuid, token)

    def _sign_request(self, method, url_query, params):
        return auth.TokenBasedAuth._sign_request(
            self, method, url_query, params)


class TestHTTPDatabaseWithCreds(
        test_http_database.TestHTTPDatabaseCtrWithCreds):

    def test_get_sync_target_inherits_token_credentials(self):
        # this test was from TestDatabaseSimpleOperations but we put it here
        # for convenience.
        self.db = _HTTPDatabase('dbase')
        self.db.set_token_credentials('user-uuid', 'auth-token')
        st = self.db.get_sync_target()
        self.assertEqual(self.db._creds, st._creds)

    def test_ctr_with_creds(self):
        db1 = _HTTPDatabase('http://dbs/db', creds={'token': {
            'uuid': 'user-uuid',
            'token': 'auth-token',
        }})
        self.assertIn('token', db1._creds)


#-----------------------------------------------------------------------------
# The following tests come from `u1db.tests.test_sync`.
#-----------------------------------------------------------------------------

def _make_local_db_and_leap_target(test, path='test'):
    test.startServer()
    db = test.request_state._create_database(os.path.basename(path))
    st = leap_backend.LeapSyncTarget.connect(
        test.getURL(path), crypto=test._soledad._crypto)
    return db, st


def _make_local_db_and_token_leap_target(test):
    db, st = _make_local_db_and_leap_target(test, 'test')
    st.set_token_credentials('user-uuid', 'auth-token')
    return db, st


target_scenarios = [
    ('token_leap', {'create_db_and_target':
                    _make_local_db_and_token_leap_target,
                    'make_app_with_state': make_token_soledad_app}),
]


class LeapDatabaseSyncTargetTests(
        test_sync.DatabaseSyncTargetTests, BaseSoledadTest):

    scenarios = (
        tests.multiply_scenarios(
            tests.DatabaseBaseTests.scenarios,
            target_scenarios))

    def test_sync_exchange(self):
        """
        Test sync exchange.

        This test was adapted to decrypt remote content before assert.
        """
        sol = _make_local_db_and_leap_target(self)
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
            last_known_trans_id=None, return_doc_cb=self.receive_doc)
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


class TestLeapDbSync(test_sync.TestDbSync, BaseSoledadTest):
    """Test db.sync remote sync shortcut"""

    scenarios = [
        ('py-http', {
            'make_app_with_state': make_soledad_app,
            'make_database_for_test': tests.make_memory_database_for_test,
        }),
        ('py-token-http', {
            'make_app_with_state': make_token_soledad_app,
            'make_database_for_test': tests.make_memory_database_for_test,
            'token': True
        }),
    ]

    oauth = False
    token = False

    def do_sync(self, target_name):
        """
        Perform sync using LeapSyncTarget and Token auth.
        """
        if self.token:
            extra = dict(creds={'token': {
                'uuid': 'user-uuid',
                'token': 'auth-token',
            }})
            target_url = self.getURL(target_name)
            return Synchronizer(
                self.db,
                leap_backend.LeapSyncTarget(
                    target_url,
                    crypto=self._soledad._crypto,
                    **extra)).sync(autocreate=True)
        else:
            return test_sync.TestDbSync.do_sync(self, target_name)

    def test_db_sync(self):
        """
        Test sync.

        Adapted to check for encrypted content.
        """
        doc1 = self.db.create_doc_from_json(tests.simple_doc)
        doc2 = self.db2.create_doc_from_json(tests.nested_doc)
        local_gen_before_sync = self.do_sync('test2.db')
        gen, _, changes = self.db.whats_changed(local_gen_before_sync)
        self.assertEqual(1, len(changes))
        self.assertEqual(doc2.doc_id, changes[0][0])
        self.assertEqual(1, gen - local_gen_before_sync)
        self.assertGetEncryptedDoc(
            self.db2, doc1.doc_id, doc1.rev, tests.simple_doc, False)
        self.assertGetEncryptedDoc(
            self.db, doc2.doc_id, doc2.rev, tests.nested_doc, False)

    def test_db_sync_autocreate(self):
        """
        Test sync.

        Adapted to check for encrypted content.
        """
        doc1 = self.db.create_doc_from_json(tests.simple_doc)
        local_gen_before_sync = self.do_sync('test3.db')
        gen, _, changes = self.db.whats_changed(local_gen_before_sync)
        self.assertEqual(0, gen - local_gen_before_sync)
        db3 = self.request_state.open_database('test3.db')
        gen, _, changes = db3.whats_changed()
        self.assertEqual(1, len(changes))
        self.assertEqual(doc1.doc_id, changes[0][0])
        self.assertGetEncryptedDoc(
            db3, doc1.doc_id, doc1.rev, tests.simple_doc, False)
        t_gen, _ = self.db._get_replica_gen_and_trans_id('test3.db')
        s_gen, _ = db3._get_replica_gen_and_trans_id('test1')
        self.assertEqual(1, t_gen)
        self.assertEqual(1, s_gen)


load_tests = tests.load_with_scenarios
