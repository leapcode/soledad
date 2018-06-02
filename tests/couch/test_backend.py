# -*- coding: utf-8 -*-
# test_couch.py
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
Test ObjectStore and Couch backend bits.
"""

import pytest
from uuid import uuid4
from six.moves.urllib.parse import urljoin
from testscenarios import TestWithScenarios
from twisted.trial import unittest

from leap.soledad.common import couch

from test_soledad.util import CouchDBTestCase
from test_soledad.u1db_tests import test_backends

from .common import COUCH_SCENARIOS


# -----------------------------------------------------------------------------
# The following tests come from `u1db.tests.test_common_backend`.
# -----------------------------------------------------------------------------

@pytest.mark.needs_couch
class TestCouchBackendImpl(CouchDBTestCase):

    def test__allocate_doc_id(self):
        db = couch.CouchDatabase.open_database(
            urljoin(self.couch_url, 'test-%s' % uuid4().hex),
            create=True)
        doc_id1 = db._allocate_doc_id()
        self.assertTrue(doc_id1.startswith('D-'))
        self.assertEqual(34, len(doc_id1))
        int(doc_id1[len('D-'):], 16)
        self.assertNotEqual(doc_id1, db._allocate_doc_id())
        self.delete_db(db._dbname)


# -----------------------------------------------------------------------------
# The following tests come from `u1db.tests.test_backends`.
# -----------------------------------------------------------------------------

@pytest.mark.needs_couch
class CouchTests(
        TestWithScenarios, test_backends.AllDatabaseTests, CouchDBTestCase):

    scenarios = COUCH_SCENARIOS


@pytest.mark.needs_couch
class CouchBackendTests(
        TestWithScenarios,
        test_backends.LocalDatabaseTests,
        CouchDBTestCase):

    scenarios = COUCH_SCENARIOS


@pytest.mark.needs_couch
class CouchValidateGenNTransIdTests(
        TestWithScenarios,
        test_backends.LocalDatabaseValidateGenNTransIdTests,
        CouchDBTestCase):

    scenarios = COUCH_SCENARIOS


@pytest.mark.needs_couch
class CouchValidateSourceGenTests(
        TestWithScenarios,
        test_backends.LocalDatabaseValidateSourceGenTests,
        CouchDBTestCase):

    scenarios = COUCH_SCENARIOS


@pytest.mark.needs_couch
class CouchWithConflictsTests(
        TestWithScenarios,
        test_backends.LocalDatabaseWithConflictsTests,
        CouchDBTestCase):

        scenarios = COUCH_SCENARIOS


# Notice: the CouchDB backend does not have indexing capabilities, so we do
# not test indexing now.

# class CouchIndexTests(test_backends.DatabaseIndexTests, CouchDBTestCase):
#
#     scenarios = COUCH_SCENARIOS
#
#     def tearDown(self):
#         self.db.delete_database()
#         test_backends.DatabaseIndexTests.tearDown(self)


@pytest.mark.needs_couch
class DatabaseNameValidationTest(unittest.TestCase):

    def test_database_name_validation(self):
        inject = couch.state.is_db_name_valid("user-deadbeef | cat /secret")
        self.assertFalse(inject)
        self.assertTrue(couch.state.is_db_name_valid("user-cafe1337"))
