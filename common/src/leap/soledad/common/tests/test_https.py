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
from unittest import skip

from testscenarios import TestWithScenarios

from leap.soledad import client

from leap.soledad.common.l2db.remote import http_client
from leap.soledad.common.tests.u1db_tests import test_backends
from leap.soledad.common.tests.u1db_tests import test_https
from leap.soledad.common.tests.util import (
    BaseSoledadTest,
    make_soledad_document_for_test,
    make_soledad_app,
    make_token_soledad_app,
)


LEAP_SCENARIOS = [
    ('http', {
        'make_database_for_test': test_backends.make_http_database_for_test,
        'copy_database_for_test': test_backends.copy_http_database_for_test,
        'make_document_for_test': make_soledad_document_for_test,
        'make_app_with_state': make_soledad_app}),
]


# -----------------------------------------------------------------------------
# The following tests come from `u1db.tests.test_https`.
# -----------------------------------------------------------------------------

def token_leap_https_sync_target(test, host, path, cert_file=None):
    _, port = test.server.server_address
    # source_replica_uid = test._soledad._dbpool.replica_uid
    creds = {'token': {'uuid': 'user-uuid', 'token': 'auth-token'}}
    if not cert_file:
        cert_file = test.cacert_pem
    st = client.http_target.SoledadHTTPSyncTarget(
        'https://%s:%d/%s' % (host, port, path),
        source_replica_uid='other-id',
        creds=creds,
        crypto=test._soledad._crypto,
        cert_file=cert_file)
    return st


@skip("Skiping tests imported from U1DB.")
class TestSoledadHTTPSyncTargetHttpsSupport(
        TestWithScenarios,
        # test_https.TestHttpSyncTargetHttpsSupport,
        BaseSoledadTest):

    scenarios = [
        ('token_soledad_https',
            {
             #'server_def': test_https.https_server_def,
             'make_app_with_state': make_token_soledad_app,
             'make_document_for_test': make_soledad_document_for_test,
             'sync_target': token_leap_https_sync_target}),
    ]

    def setUp(self):
        # the parent constructor undoes our SSL monkey patch to ensure tests
        # run smoothly with standard u1db.
        test_https.TestHttpSyncTargetHttpsSupport.setUp(self)
        # so here monkey patch again to test our functionality.
        api = client.api
        http_client._VerifiedHTTPSConnection = api.VerifiedHTTPSConnection
        client.api.SOLEDAD_CERT = http_client.CA_CERTS

    def test_cannot_verify_cert(self):
        self.startServer()
        # don't print expected traceback server-side
        self.server.handle_error = lambda req, cli_addr: None
        self.request_state._create_database('test')
        remote_target = self.getSyncTarget(
            'localhost', 'test', cert_file=http_client.CA_CERTS)
        d = remote_target.record_sync_info('other-id', 2, 'T-id')

        def _assert_raises(result):
            from twisted.python.failure import Failure
            if isinstance(result, Failure):
                from OpenSSL.SSL import Error
                error = result.value.message[0].value
                if isinstance(error, Error):
                    msg = error.message[0][2]
                    self.assertEqual("certificate verify failed", msg)
                    return
            self.fail("certificate verification should have failed.")

        d.addCallbacks(_assert_raises, _assert_raises)
        return d

    def test_working(self):
        """
        Test that SSL connections work well.

        This test was adapted to patch Soledad's HTTPS connection custom class
        with the intended CA certificates.
        """
        self.startServer()
        db = self.request_state._create_database('test')
        remote_target = self.getSyncTarget('localhost', 'test')
        d = remote_target.record_sync_info('other-id', 2, 'T-id')
        d.addCallback(lambda _:
                      self.assertEqual(
                          (2, 'T-id'),
                          db._get_replica_gen_and_trans_id('other-id')
                      ))
        d.addCallback(lambda _: remote_target.close())
        return d

    def test_host_mismatch(self):
        """
        This test is disabled because soledad's twisted-based http agent uses
        pyOpenSSL, which will complain if we try to use an IP to connect to
        the remote host (see the original test in u1db_tests/test_https.py).
        """
        pass
