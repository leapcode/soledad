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
import shutil
import tempfile
try:
    import simplejson as json
except ImportError:
    import json  # noqa
import hashlib


from leap.soledad.server import URLToAuth
from leap.common.testing.basetest import BaseLeapTest


class SoledadServerTestCase(BaseLeapTest):
    """
    Tests that guarantee that data will always be encrypted when syncing.
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
        authmap = URLToAuth(uuid)
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
        authmap = URLToAuth(uuid)
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
