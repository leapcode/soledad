# -*- coding: utf-8 -*-
# test_http_client.py
# Copyright (C) 2013-2016 LEAP
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
Test Leap backend bits: sync target
"""
import json

from testscenarios import TestWithScenarios

from leap.soledad.client import auth
from leap.soledad.common.l2db.remote import http_client
from test_soledad.u1db_tests import test_http_client
from leap.soledad.server.auth import SoledadTokenAuthMiddleware


# -----------------------------------------------------------------------------
# The following tests come from `u1db.tests.test_http_client`.
# -----------------------------------------------------------------------------

class TestSoledadClientBase(
        TestWithScenarios,
        test_http_client.TestHTTPClientBase):

    """
    This class should be used to test Token auth.
    """

    def getClient(self, **kwds):
        cli = self.getClientWithToken(**kwds)
        if 'creds' not in kwds:
            cli.set_token_credentials('user-uuid', 'auth-token')
        return cli

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

    def app(self, environ, start_response):
        res = test_http_client.TestHTTPClientBase.app(
            self, environ, start_response)
        if res is not None:
            return res
        # mime solead application here.
        if '/token' in environ['PATH_INFO']:
            auth = environ.get(SoledadTokenAuthMiddleware.HTTP_AUTH_KEY)
            if not auth:
                start_response("401 Unauthorized",
                               [('Content-Type', 'application/json')])
                return [
                    json.dumps(
                        {"error": "unauthorized",
                         "message": "no token found in environment"})
                ]
            scheme, encoded = auth.split(None, 1)
            if scheme.lower() != 'token':
                start_response("401 Unauthorized",
                               [('Content-Type', 'application/json')])
                return [json.dumps({"error": "unauthorized",
                                    "message": "unknown scheme: %s" % scheme})]
            uuid, token = encoded.decode('base64').split(':', 1)
            if uuid != 'user-uuid' and token != 'auth-token':
                return Exception("Incorrect address or token.")
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
