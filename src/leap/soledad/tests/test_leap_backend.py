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
try:
    import simplejson as json
except ImportError:
    import json  # noqa
import cStringIO


from leap.soledad.backends import leap_backend
from leap.soledad.server import SoledadApp


from leap.soledad.tests import u1db_tests as tests
from leap.soledad.tests.u1db_tests.test_remote_sync_target import (
    make_oauth_http_app,
)
from leap.soledad.tests import BaseSoledadTest
from leap.soledad.tests.u1db_tests import test_backends
from leap.soledad.tests.u1db_tests import test_http_database
from leap.soledad.tests.u1db_tests import test_http_client
from leap.soledad.tests.u1db_tests import test_document
from leap.soledad.tests.u1db_tests import test_remote_sync_target
from leap.soledad.tests.u1db_tests import test_https


#-----------------------------------------------------------------------------
# The following tests come from `u1db.tests.test_backends`.
#-----------------------------------------------------------------------------

def make_leap_document_for_test(test, doc_id, rev, content,
                                has_conflicts=False):
    return leap_backend.LeapDocument(
        doc_id, rev, content, has_conflicts=has_conflicts)


def make_soledad_app(state):
    return SoledadApp(state)


LEAP_SCENARIOS = [
    ('http', {
        'make_database_for_test': test_backends.make_http_database_for_test,
        'copy_database_for_test': test_backends.copy_http_database_for_test,
        'make_document_for_test': make_leap_document_for_test,
        'make_app_with_state': make_soledad_app}),
]


class LeapTests(test_backends.AllDatabaseTests, BaseSoledadTest):

    scenarios = LEAP_SCENARIOS


#-----------------------------------------------------------------------------
# The following tests come from `u1db.tests.test_http_client`.
#-----------------------------------------------------------------------------

class TestLeapClientBase(test_http_client.TestHTTPClientBase):
    """
    This class should be used to test Token auth.
    """
    pass


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
        doc = leap_backend.LeapDocument('i')
        doc.content = {}
        enc_json = leap_backend.encrypt_doc_json(
            self._soledad._crypto, doc.doc_id, doc.get_json())
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


def oauth_leap_sync_target(test, path):
    st = leap_sync_target(test, '~/' + path)
    st.set_oauth_credentials(tests.consumer1.key, tests.consumer1.secret,
                             tests.token1.key, tests.token1.secret)
    return st


class TestLeapSyncTarget(
    test_remote_sync_target.TestRemoteSyncTargets, BaseSoledadTest):

    scenarios = [
        ('http', {'make_app_with_state': make_soledad_app,
                  'make_document_for_test': make_leap_document_for_test,
                  'sync_target': leap_sync_target}),
        ('oauth_http', {'make_app_with_state': make_oauth_http_app,
                        'make_document_for_test': make_leap_document_for_test,
                        'sync_target': oauth_leap_sync_target}),
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
        # (possibly) decrypt and compare
        doc2 = db.get_doc('doc-here')
        if leap_backend.ENC_SCHEME_KEY in doc2.content:
            doc2.set_json(
                leap_backend.decrypt_doc_json(
                    self._soledad._crypto, doc2.doc_id, doc2.get_json()))
        self.assertEqual(doc, doc2)

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
        # -- (possibly) decrypt and compare
        tmpdoc = db.get_doc('doc-here')
        if leap_backend.ENC_SCHEME_KEY in tmpdoc.content:
            tmpdoc.set_json(
                leap_backend.decrypt_doc_json(
                    self._soledad._crypto, tmpdoc.doc_id, tmpdoc.get_json()))
        self.assertEqual(doc1, tmpdoc)
        # -- end of decrypt and compare
        self.assertEqual(
            (10, 'T-sid'), db._get_replica_gen_and_trans_id('replica'))
        self.assertEqual([], other_changes)
        # retry
        trigger_ids = []
        new_gen, trans_id = remote_target.sync_exchange(
            [(doc2, 11, 'T-sud')], 'replica', last_known_generation=0,
            last_known_trans_id=None, return_doc_cb=receive_doc)
        # -- (possibly) decrypt and compare
        tmpdoc = db.get_doc('doc-here2')
        if leap_backend.ENC_SCHEME_KEY in tmpdoc.content:
            tmpdoc.set_json(
                leap_backend.decrypt_doc_json(
                    self._soledad._crypto, tmpdoc.doc_id, tmpdoc.get_json()))
        self.assertEqual(doc2, tmpdoc)
        # -- end of decrypt and compare
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
        # -- (possibly) decrypt and compare
        tmpdoc = db.get_doc('doc-here')
        if leap_backend.ENC_SCHEME_KEY in tmpdoc.content:
            tmpdoc.set_json(
                leap_backend.decrypt_doc_json(
                    self._soledad._crypto, tmpdoc.doc_id, tmpdoc.get_json()))
        self.assertEqual(doc, tmpdoc)
        # -- end of decrypt and compare

#-----------------------------------------------------------------------------
# The following tests come from `u1db.tests.test_https`.
#-----------------------------------------------------------------------------

def oauth_https_sync_target(test, host, path):
    _, port = test.server.server_address
    st = leap_backend.LeapSyncTarget(
        'https://%s:%d/~/%s' % (host, port, path),
        crypto=test._soledad._crypto)
    st.set_oauth_credentials(tests.consumer1.key, tests.consumer1.secret,
                             tests.token1.key, tests.token1.secret)
    return st


class TestLeapSyncTargetHttpsSupport(test_https.TestHttpSyncTargetHttpsSupport,
                                     BaseSoledadTest):

    scenarios = [
        ('oauth_https', {'server_def': test_https.https_server_def,
                         'make_app_with_state': make_oauth_http_app,
                         'make_document_for_test': make_leap_document_for_test,
                         'sync_target': oauth_https_sync_target,
                         }), ]

load_tests = tests.load_with_scenarios
