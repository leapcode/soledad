# -*- coding: utf-8 -*-
# test_soledad_doc.py
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
Test Leap backend bits: soledad docs
"""
import pytest

from testscenarios import TestWithScenarios

from test_soledad.u1db_tests import test_document
from test_soledad.util import BaseSoledadTest
from test_soledad.util import make_soledad_document_for_test


# -----------------------------------------------------------------------------
# The following tests come from `u1db.tests.test_document`.
# -----------------------------------------------------------------------------

@pytest.mark.usefixtures('method_tmpdir')
class TestSoledadDocument(
        TestWithScenarios,
        test_document.TestDocument, BaseSoledadTest):

    scenarios = ([(
        'leap', {
            'make_document_for_test': make_soledad_document_for_test})])


@pytest.mark.usefixtures('method_tmpdir')
class TestSoledadPyDocument(
        TestWithScenarios,
        test_document.TestPyDocument, BaseSoledadTest):

    scenarios = ([(
        'leap', {
            'make_document_for_test': make_soledad_document_for_test})])
