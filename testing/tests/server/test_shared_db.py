# -*- coding: utf-8 -*-
# test_shared_db.py
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
Tests for the shared db on server side.
"""


import pytest

from twisted.trial import unittest

from leap.soledad.client.shared_db import SoledadSharedDatabase
from leap.soledad.common.document import SoledadDocument
from leap.soledad.common.l2db.errors import RevisionConflict


class SharedDbTests(unittest.TestCase):
    """
    """

    URL = 'http://127.0.0.1:2424/shared'
    CREDS = {'token': {'uuid': 'an-uuid', 'token': 'an-auth-token'}}

    @pytest.fixture(autouse=True)
    def soledad_client(self, soledad_server, soledad_dbs):
        soledad_dbs('an-uuid')
        self._db = SoledadSharedDatabase.open_database(self.URL, self.CREDS)

    @pytest.mark.thisone
    def test_doc_update_succeeds(self):
        doc_id = 'some-random-doc'
        self.assertIsNone(self._db.get_doc(doc_id))
        # create a document in shared db
        doc = SoledadDocument(doc_id=doc_id)
        self._db.put_doc(doc)
        # update that document
        expected = {'new': 'content'}
        doc.content = expected
        self._db.put_doc(doc)
        # ensure expected content was saved
        doc = self._db.get_doc(doc_id)
        self.assertEqual(expected, doc.content)

    @pytest.mark.thisone
    def test_doc_update_fails_with_wrong_rev(self):
        # create a document in shared db
        doc_id = 'some-random-doc'
        self.assertIsNone(self._db.get_doc(doc_id))
        # create a document in shared db
        doc = SoledadDocument(doc_id=doc_id)
        self._db.put_doc(doc)
        # try to update document without including revision of old version
        doc.rev = 'wrong-rev'
        self.assertRaises(RevisionConflict, self._db.put_doc, doc)
