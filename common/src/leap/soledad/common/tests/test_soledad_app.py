# -*- coding: utf-8 -*-
# test_soledad_app.py
# Copyright (C) 2014 LEAP
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


from testscenarios import TestWithScenarios

from leap.soledad.common.tests.util import BaseSoledadTest
from leap.soledad.common.tests.util import make_soledad_document_for_test
from leap.soledad.common.tests.util import make_soledad_app
from leap.soledad.common.tests.util import make_token_soledad_app
from leap.soledad.common.tests.util import make_token_http_database_for_test
from leap.soledad.common.tests.util import copy_token_http_database_for_test
from leap.soledad.common.tests.u1db_tests import test_backends


# -----------------------------------------------------------------------------
# The following tests come from `u1db.tests.test_backends`.
# -----------------------------------------------------------------------------

LEAP_SCENARIOS = [
    ('http', {
        'make_database_for_test': test_backends.make_http_database_for_test,
        'copy_database_for_test': test_backends.copy_http_database_for_test,
        'make_document_for_test': make_soledad_document_for_test,
        'make_app_with_state': make_soledad_app}),
]


class SoledadTests(
        TestWithScenarios, test_backends.AllDatabaseTests, BaseSoledadTest):

    scenarios = LEAP_SCENARIOS + [
        ('token_http', {
            'make_database_for_test': make_token_http_database_for_test,
            'copy_database_for_test': copy_token_http_database_for_test,
            'make_document_for_test': make_soledad_document_for_test,
            'make_app_with_state': make_token_soledad_app,
        })
    ]
