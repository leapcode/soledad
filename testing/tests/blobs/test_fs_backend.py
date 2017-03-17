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
import mock
import os
import base64
import pytest


class FilesystemBackendTestCase(unittest.TestCase):

    def test_tag_header(self):
        _blobs.open = lambda x: BytesIO('A' * 40 + 'B' * 16)
        expected_tag = base64.urlsafe_b64encode('B' * 16)
        expected_method = Mock()
        backend = _blobs.FilesystemBlobsBackend()
        request = Mock(responseHeaders=Mock(setRawHeaders=expected_method))
        backend.tag_header('user', 'blob_id', request)

        expected_method.assert_called_once_with('Tag', [expected_tag])

    def test_read_blob(self):
        render_mock = Mock()
        _blobs.static.File = Mock(return_value=render_mock)
        backend = _blobs.FilesystemBlobsBackend()
        request = object()
        backend._get_path = Mock(return_value='path')
        backend.read_blob('user', 'blob_id', request)

        backend._get_path.assert_called_once_with('user', 'blob_id')
        ctype = 'application/octet-stream'
        _blobs.static.File.assert_called_once_with('path', defaultType=ctype)
        render_mock.render_GET.assert_called_once_with(request)

    @mock.patch.object(os.path, 'isfile')
    def test_cannot_overwrite(self, isfile):
        isfile.return_value = True
        backend = _blobs.FilesystemBlobsBackend()
        backend._get_path = Mock(return_value='path')
        with pytest.raises(_blobs.BlobAlreadyExists):
            backend.write_blob('user', 'blob_id', 'request')

    @pytest.mark.usefixtures("method_tmpdir")
    @mock.patch.object(os.path, 'isfile')
    def test_write_cannot_exceed_quota(self, isfile):
        isfile.return_value = False
        backend = _blobs.FilesystemBlobsBackend()
        backend._get_path = Mock(return_value=self.tempdir)
        request = Mock()

        backend.get_total_storage = lambda x: 100
        backend.quota = 90
        backend.write_blob('user', 'blob_id', request)

        request.setResponseCode.assert_called_once_with(507)
        request.write.assert_called_once_with('Quota Exceeded!')
        request.finish.assert_called_once()

    def test_get_path_partitioning(self):
        backend = _blobs.FilesystemBlobsBackend()
        backend.path = '/somewhere/'
        path = backend._get_path('user', 'blob_id')
        assert path == '/somewhere/user/b/blo/blob_i/blob_id'
