# -*- coding: utf-8 -*-
# test_api.py
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
Tests for soledad api.
"""

from mock import MagicMock

from test_soledad.util import BaseSoledadTest


class ApiTestCase(BaseSoledadTest):

    def test_recovery_code_creation(self):
        recovery_code_mock = MagicMock()
        generated_code = '4645a2f8997e5d0d'
        recovery_code_mock.generate.return_value = generated_code
        self._soledad._recovery_code = recovery_code_mock

        code = self._soledad.create_recovery_code()

        self.assertEqual(generated_code, code)
