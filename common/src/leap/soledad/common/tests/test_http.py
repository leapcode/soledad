# -*- coding: utf-8 -*-
# test_http.py
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
Test Leap backend bits: test http database
"""
from u1db.remote import http_database

from leap.soledad.client import auth

from leap.soledad.common.tests import u1db_tests as tests
from leap.soledad.common.tests.u1db_tests import test_http_database


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


load_tests = tests.load_with_scenarios
