# -*- coding: utf-8 -*-
# test_sync_target.py
# Copyright (C) 2013, 2014 LEAP
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
Test Leap backend bits: https
"""
from leap.soledad.common.tests import BaseSoledadTest
from leap.soledad.common.tests import test_sync_target as test_st
from leap.soledad.common.tests import u1db_tests as tests
from leap.soledad.common.tests.u1db_tests import test_backends
from leap.soledad.common.tests.u1db_tests import test_https

from leap.soledad import client
from leap.soledad.server import SoledadApp

from u1db.remote import http_client


def make_soledad_app(state):
    return SoledadApp(state)

LEAP_SCENARIOS = [
    ('http', {
        'make_database_for_test': test_backends.make_http_database_for_test,
        'copy_database_for_test': test_backends.copy_http_database_for_test,
        'make_document_for_test': test_st.make_leap_document_for_test,
        'make_app_with_state': test_st.make_soledad_app}),
]


#-----------------------------------------------------------------------------
# The following tests come from `u1db.tests.test_https`.
#-----------------------------------------------------------------------------

def token_leap_https_sync_target(test, host, path):
    _, port = test.server.server_address
    st = client.target.SoledadSyncTarget(
        'https://%s:%d/%s' % (host, port, path),
        crypto=test._soledad._crypto)
    st.set_token_credentials('user-uuid', 'auth-token')
    return st


class TestSoledadSyncTargetHttpsSupport(
        test_https.TestHttpSyncTargetHttpsSupport,
        BaseSoledadTest):

    scenarios = [
        ('token_soledad_https',
            {'server_def': test_https.https_server_def,
             'make_app_with_state': test_st.make_token_soledad_app,
             'make_document_for_test': test_st.make_leap_document_for_test,
             'sync_target': token_leap_https_sync_target}),
    ]

    def setUp(self):
        # the parent constructor undoes our SSL monkey patch to ensure tests
        # run smoothly with standard u1db.
        test_https.TestHttpSyncTargetHttpsSupport.setUp(self)
        # so here monkey patch again to test our functionality.
        http_client._VerifiedHTTPSConnection = client.VerifiedHTTPSConnection
        client.SOLEDAD_CERT = http_client.CA_CERTS

    def test_working(self):
        """
        Test that SSL connections work well.

        This test was adapted to patch Soledad's HTTPS connection custom class
        with the intended CA certificates.
        """
        self.startServer()
        db = self.request_state._create_database('test')
        self.patch(client, 'SOLEDAD_CERT', self.cacert_pem)
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
        self.patch(client, 'SOLEDAD_CERT', self.cacert_pem)
        remote_target = self.getSyncTarget('127.0.0.1', 'test')
        self.assertRaises(
            http_client.CertificateError, remote_target.record_sync_info,
            'other-id', 2, 'T-id')

load_tests = tests.load_with_scenarios
