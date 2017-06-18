# -*- coding: utf-8 -*-
# test_command.py
# Copyright (C) 2015 LEAP
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
Tests for command execution using a validator function for arguments.
"""
from twisted.trial import unittest
from leap.soledad.common.command import exec_validated_cmd


def validator(arg):
    return True if arg is 'valid' else False


class ExecuteValidatedCommandTest(unittest.TestCase):

    def test_argument_validation(self):
        status, out = exec_validated_cmd("command", "invalid arg", validator)
        self.assertEquals(status, 1)
        self.assertEquals(out, "invalid argument")
        status, out = exec_validated_cmd("echo", "valid", validator)
        self.assertEquals(status, 0)
        self.assertEquals(out, "valid\n")

    def test_return_status_code_success(self):
        status, out = exec_validated_cmd("echo", "arg")
        self.assertEquals(status, 0)
        self.assertEquals(out, "arg\n")

    def test_handle_command_with_spaces(self):
        status, out = exec_validated_cmd("echo I am", "an argument")
        self.assertEquals(status, 0, out)
        self.assertEquals(out, "I am an argument\n")

    def test_handle_oserror_on_invalid_command(self):
        status, out = exec_validated_cmd("inexistent command with", "args")
        self.assertEquals(status, 1)
        self.assertIn("No such file or directory", out)

    def test_return_status_code_number_on_failure(self):
        status, out = exec_validated_cmd("ls", "user-bebacafe")
        self.assertNotEquals(status, 0)
        self.assertIn('No such file or directory\n', out)
