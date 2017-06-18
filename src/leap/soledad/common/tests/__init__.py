# -*- coding: utf-8 -*-
# __init__.py
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
Tests to make sure Soledad provides U1DB functionality and more.
"""


import os


def load_tests():
    """
    Build a test suite that includes all tests in leap.soledad.common.tests
    but does not include tests in the u1db_tests/ subfolder. The reason for
    not including those tests are:

        1. they by themselves only test u1db functionality in the u1db module
           (despite we use them as basis for testing soledad functionalities).

        2. they would fail because we monkey patch u1db's remote http server
           to add soledad functionality we need.
    """
    import unittest
    import glob
    import imp
    tests_prefix = os.path.join(
        '.', 'src', 'leap', 'soledad', 'common', 'tests')
    suite = unittest.TestSuite()
    for testcase in glob.glob(os.path.join(tests_prefix, 'test_*.py')):
        modname = os.path.basename(os.path.splitext(testcase)[0])
        f, pathname, description = imp.find_module(modname, [tests_prefix])
        module = imp.load_module(modname, f, pathname, description)
        suite.addTest(unittest.TestLoader().loadTestsFromModule(module))
    return suite
