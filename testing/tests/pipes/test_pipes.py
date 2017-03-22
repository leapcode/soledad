# -*- coding: utf-8 -*-
# test_pipes.py
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
Tests for streaming components.
"""
from twisted.trial import unittest
from leap.soledad.client._pipes import TruncatedTailPipe


class TruncatedTailTestCase(unittest.TestCase):

    def test_tail_truncating_pipe(self):
        pipe = TruncatedTailPipe(tail_size=20)
        payload = 'A' * 100 + 'B' * 20
        for data in payload:
            pipe.write(data)
        result = pipe.close()
        assert result.getvalue() == 'A' * 100
