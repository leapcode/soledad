# -*- coding: utf-8 -*-
# test_url_mapper.py
# Copyright (C) 2017 LEAP
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

from twisted.trial import unittest
from uuid import uuid4

from leap.soledad.server.url_mapper import URLMapper


class URLMapperTestCase(unittest.TestCase):
    """
    Test if the URLMapper behaves as expected.

    The following table lists the authorized actions among all possible
    u1db remote actions:

        URL path                      | Authorized actions
        --------------------------------------------------
        /                             | GET
        /shared-db                    | GET
        /shared-db/docs               | -
        /shared-db/doc/{id}           | -
        /shared-db/sync-from/{source} | -
        /user-db                      | -
        /user-db/docs                 | -
        /user-db/doc/{id}             | -
        /user-db/sync-from/{source}   | GET, PUT, POST
    """

    def setUp(self):
        self._uuid = uuid4().hex
        self._urlmap = URLMapper()
        self._dbname = 'user-%s' % self._uuid

    def test_root_authorized(self):
        match = self._urlmap.match('/', 'GET')
        self.assertIsNotNone(match)

    def test_shared_authorized(self):
        self.assertIsNotNone(self._urlmap.match('/shared', 'GET'))

    def test_shared_unauthorized(self):
        self.assertIsNone(self._urlmap.match('/shared', 'PUT'))
        self.assertIsNone(self._urlmap.match('/shared', 'DELETE'))
        self.assertIsNone(self._urlmap.match('/shared', 'POST'))

    def test_shared_docs_unauthorized(self):
        self.assertIsNone(self._urlmap.match('/shared/docs', 'GET'))
        self.assertIsNone(self._urlmap.match('/shared/docs', 'PUT'))
        self.assertIsNone(self._urlmap.match('/shared/docs', 'DELETE'))
        self.assertIsNone(self._urlmap.match('/shared/docs', 'POST'))

    def test_shared_doc_authorized(self):
        match = self._urlmap.match('/shared/doc/x', 'GET')
        self.assertIsNotNone(match)
        self.assertEqual('x', match.get('id'))

        match = self._urlmap.match('/shared/doc/x', 'PUT')
        self.assertIsNotNone(match)
        self.assertEqual('x', match.get('id'))

        match = self._urlmap.match('/shared/doc/x', 'DELETE')
        self.assertIsNotNone(match)
        self.assertEqual('x', match.get('id'))

    def test_shared_doc_unauthorized(self):
        self.assertIsNone(self._urlmap.match('/shared/doc/x', 'POST'))

    def test_shared_sync_unauthorized(self):
        self.assertIsNone(self._urlmap.match('/shared/sync-from/x', 'GET'))
        self.assertIsNone(self._urlmap.match('/shared/sync-from/x', 'PUT'))
        self.assertIsNone(self._urlmap.match('/shared/sync-from/x', 'DELETE'))
        self.assertIsNone(self._urlmap.match('/shared/sync-from/x', 'POST'))

    def test_user_db_unauthorized(self):
        dbname = self._dbname
        self.assertIsNone(self._urlmap.match('/%s' % dbname, 'GET'))
        self.assertIsNone(self._urlmap.match('/%s' % dbname, 'PUT'))
        self.assertIsNone(self._urlmap.match('/%s' % dbname, 'DELETE'))
        self.assertIsNone(self._urlmap.match('/%s' % dbname, 'POST'))

    def test_user_db_docs_unauthorized(self):
        dbname = self._dbname
        self.assertIsNone(self._urlmap.match('/%s/docs' % dbname, 'GET'))
        self.assertIsNone(self._urlmap.match('/%s/docs' % dbname, 'PUT'))
        self.assertIsNone(self._urlmap.match('/%s/docs' % dbname, 'DELETE'))
        self.assertIsNone(self._urlmap.match('/%s/docs' % dbname, 'POST'))

    def test_user_db_doc_unauthorized(self):
        dbname = self._dbname
        self.assertIsNone(self._urlmap.match('/%s/doc/x' % dbname, 'GET'))
        self.assertIsNone(self._urlmap.match('/%s/doc/x' % dbname, 'PUT'))
        self.assertIsNone(self._urlmap.match('/%s/doc/x' % dbname, 'DELETE'))
        self.assertIsNone(self._urlmap.match('/%s/doc/x' % dbname, 'POST'))

    def test_user_db_sync_authorized(self):
        uuid = self._uuid
        dbname = self._dbname
        match = self._urlmap.match('/%s/sync-from/x' % dbname, 'GET')
        self.assertEqual(uuid, match.get('uuid'))
        self.assertEqual('x', match.get('source_replica_uid'))

        match = self._urlmap.match('/%s/sync-from/x' % dbname, 'PUT')
        self.assertEqual(uuid, match.get('uuid'))
        self.assertEqual('x', match.get('source_replica_uid'))

        match = self._urlmap.match('/%s/sync-from/x' % dbname, 'POST')
        self.assertEqual(uuid, match.get('uuid'))
        self.assertEqual('x', match.get('source_replica_uid'))

    def test_user_db_sync_unauthorized(self):
        dbname = self._dbname
        self.assertIsNone(
            self._urlmap.match('/%s/sync-from/x' % dbname, 'DELETE'))
