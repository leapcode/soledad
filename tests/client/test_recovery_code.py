# -*- CODing: utf-8 -*-
# test_recovery_code.py
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
Tests for recovery code generation.
"""
import binascii

from mock import patch
from twisted.trial import unittest
from leap.soledad.client._recovery_code import RecoveryCode


class RecoveryCodeTestCase(unittest.TestCase):

    @patch('leap.soledad.client._recovery_code.os.urandom')
    def test_generate_recovery_code(self, mock_os_urandom):
        generated_random_code = '123456'
        mock_os_urandom.return_value = generated_random_code
        recovery_code = RecoveryCode()

        code = recovery_code.generate()

        mock_os_urandom.assert_called_with(RecoveryCode.code_length)
        self.assertEqual(binascii.hexlify(generated_random_code), code)
