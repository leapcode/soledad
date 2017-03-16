# -*- coding: utf-8 -*-
# test_crypto.py
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
Tests for blobs backend on server side.
"""
from twisted.trial import unittest
from leap.soledad.server import _blobs
from io import BytesIO
from mock import Mock
import base64


class FilesystemBackendTestCase(unittest.TestCase):

    def test_tag_header(self):
        _blobs.open = lambda x: BytesIO('A' * 40 + 'B' * 16)
        expected_tag = base64.urlsafe_b64encode('B' * 16)
        expected_method = Mock()
        backend = _blobs.FilesystemBlobsBackend()
        request = Mock(responseHeaders=Mock(setRawHeaders=expected_method))
        backend.tag_header('user', 'blob_id', request)

        expected_method.assert_called_once_with('Tag', [expected_tag])
