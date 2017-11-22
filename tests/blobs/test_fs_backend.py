# -*- coding: utf-8 -*-
# test_fs_backend.py
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
from twisted.internet import defer
from twisted.web.test.test_web import DummyRequest
from leap.common.files import mkdir_p
from leap.soledad.server import _blobs
from io import BytesIO
from mock import Mock
import mock
import os
import base64
import json
import pytest


class FilesystemBackendTestCase(unittest.TestCase):

    @pytest.mark.usefixtures("method_tmpdir")
    @mock.patch.object(_blobs, 'open')
    def test_tag_header(self, open_mock):
        open_mock.return_value = BytesIO('A' * 40 + 'B' * 16)
        expected_tag = base64.urlsafe_b64encode('B' * 16)
        expected_method = Mock()
        backend = _blobs.FilesystemBlobsBackend(blobs_path=self.tempdir)
        # write a blob...
        path = backend._get_path('user', 'blob_id', '')
        mkdir_p(os.path.split(path)[0])
        with open(path, "w") as f:
            f.write("bl0b")
        # ...and get its tag
        request = Mock(responseHeaders=Mock(setRawHeaders=expected_method))
        backend.add_tag_header('user', 'blob_id', request)

        expected_method.assert_called_once_with('Tag', [expected_tag])

    @pytest.mark.usefixtures("method_tmpdir")
    @mock.patch.object(_blobs.static, 'File')
    @mock.patch.object(_blobs.FilesystemBlobsBackend, '_get_path',
                       Mock(return_value='path'))
    def test_read_blob(self, file_mock):
        render_mock = Mock()
        file_mock.return_value = render_mock
        backend = _blobs.FilesystemBlobsBackend(blobs_path=self.tempdir)
        request = DummyRequest([''])
        backend.read_blob('user', 'blob_id', request)

        backend._get_path.assert_called_once_with('user', 'blob_id', '')
        ctype = 'application/octet-stream'
        _blobs.static.File.assert_called_once_with('path', defaultType=ctype)
        render_mock.render_GET.assert_called_once_with(request)

    @pytest.mark.usefixtures("method_tmpdir")
    @mock.patch.object(os.path, 'isfile')
    @mock.patch.object(_blobs.FilesystemBlobsBackend, '_get_path',
                       Mock(return_value='path'))
    @defer.inlineCallbacks
    def test_cannot_overwrite(self, isfile):
        isfile.return_value = True
        backend = _blobs.FilesystemBlobsBackend(blobs_path=self.tempdir)
        request = DummyRequest([''])
        yield backend.write_blob('user', 'blob_id', request)
        self.assertEquals(request.written[0], "Blob already exists: blob_id")
        self.assertEquals(request.responseCode, 409)

    @pytest.mark.usefixtures("method_tmpdir")
    @mock.patch.object(os.path, 'isfile')
    @defer.inlineCallbacks
    def test_write_cannot_exceed_quota(self, isfile):
        isfile.return_value = False
        backend = _blobs.FilesystemBlobsBackend(blobs_path=self.tempdir)
        request = Mock()

        backend.get_total_storage = lambda x: 100
        backend.quota = 90
        yield backend.write_blob('user', 'blob_id', request)

        request.setResponseCode.assert_called_once_with(507)
        request.write.assert_called_once_with('Quota Exceeded!')

    @pytest.mark.usefixtures("method_tmpdir")
    def test_get_path_partitioning_by_default(self):
        backend = _blobs.FilesystemBlobsBackend(blobs_path=self.tempdir)
        backend.path = '/somewhere/'
        path = backend._get_path('user', 'blob_id', '')
        expected = '/somewhere/user/default/b/blo/blob_i/blob_id'
        self.assertEquals(path, expected)

    @pytest.mark.usefixtures("method_tmpdir")
    def test_get_path_custom(self):
        backend = _blobs.FilesystemBlobsBackend(blobs_path=self.tempdir)
        backend.path = '/somewhere/'
        path = backend._get_path('user', 'blob_id', 'wonderland')
        expected = '/somewhere/user/wonderland/b/blo/blob_i/blob_id'
        self.assertEquals(expected, path)

    @pytest.mark.usefixtures("method_tmpdir")
    def test_get_path_namespace_traversal_raises(self):
        backend = _blobs.FilesystemBlobsBackend(blobs_path=self.tempdir)
        backend.path = '/somewhere/'
        with pytest.raises(Exception):
            backend._get_path('user', 'blob_id', '..')

    @pytest.mark.usefixtures("method_tmpdir")
    @mock.patch('leap.soledad.server._blobs.os.walk')
    def test_list_blobs(self, walk_mock):
        backend = _blobs.FilesystemBlobsBackend(blobs_path=self.tempdir)
        _ = None
        walk_mock.return_value = [('', _, ['blob_0']), ('', _, ['blob_1'])]
        result = json.loads(backend.list_blobs('user', DummyRequest([''])))
        self.assertEquals(result, ['blob_0', 'blob_1'])

    @pytest.mark.usefixtures("method_tmpdir")
    @mock.patch('leap.soledad.server._blobs.os.walk')
    def test_list_blobs_limited_by_namespace(self, walk_mock):
        backend = _blobs.FilesystemBlobsBackend(self.tempdir)
        _ = None
        walk_mock.return_value = [('', _, ['blob_0']), ('', _, ['blob_1'])]
        result = json.loads(backend.list_blobs('user', DummyRequest(['']),
                                               namespace='incoming'))
        self.assertEquals(result, ['blob_0', 'blob_1'])
        target_dir = os.path.join(self.tempdir, 'user', 'incoming')
        walk_mock.assert_called_once_with(target_dir)

    @pytest.mark.usefixtures("method_tmpdir")
    def test_path_validation_on_read_blob(self):
        blobs_path, request = self.tempdir, DummyRequest([''])
        backend = _blobs.FilesystemBlobsBackend(blobs_path=blobs_path)
        with pytest.raises(Exception):
            backend.read_blob('..', '..', request)
        with pytest.raises(Exception):
            backend.read_blob('user', '../../../', request)
        with pytest.raises(Exception):
            backend.read_blob('../../../', 'blob_id', request)
        with pytest.raises(Exception):
            backend.read_blob('user', 'blob_id', request, namespace='..')

    @pytest.mark.usefixtures("method_tmpdir")
    @defer.inlineCallbacks
    def test_path_validation_on_write_blob(self):
        blobs_path, request = self.tempdir, DummyRequest([''])
        backend = _blobs.FilesystemBlobsBackend(blobs_path=blobs_path)
        with pytest.raises(Exception):
            yield backend.write_blob('..', '..', request)
        with pytest.raises(Exception):
            yield backend.write_blob('user', '../../../', request)
        with pytest.raises(Exception):
            yield backend.write_blob('../../../', 'id1', request)
        with pytest.raises(Exception):
            yield backend.write_blob('user', 'id2', request, namespace='..')

    @pytest.mark.usefixtures("method_tmpdir")
    @mock.patch('leap.soledad.server._blobs.os.unlink')
    def test_delete_blob(self, unlink_mock):
        backend = _blobs.FilesystemBlobsBackend(blobs_path=self.tempdir)
        request = DummyRequest([''])
        # write a blob...
        path = backend._get_path('user', 'blob_id', '')
        mkdir_p(os.path.split(path)[0])
        with open(path, "w") as f:
            f.write("bl0b")
        # ...and delete it
        backend.delete_blob('user', 'blob_id', request)
        unlink_mock.assert_any_call(backend._get_path('user',
                                                      'blob_id'))
        unlink_mock.assert_any_call(backend._get_path('user',
                                                      'blob_id') + '.flags')

    @pytest.mark.usefixtures("method_tmpdir")
    @mock.patch('leap.soledad.server._blobs.os.unlink')
    def test_delete_blob_custom_namespace(self, unlink_mock):
        backend = _blobs.FilesystemBlobsBackend(blobs_path=self.tempdir)
        request = DummyRequest([''])
        # write a blob...
        path = backend._get_path('user', 'blob_id', 'trash')
        mkdir_p(os.path.split(path)[0])
        with open(path, "w") as f:
            f.write("bl0b")
        # ...and delete it
        backend.delete_blob('user', 'blob_id', request, namespace='trash')
        unlink_mock.assert_any_call(backend._get_path('user',
                                                      'blob_id',
                                                      'trash'))
        unlink_mock.assert_any_call(backend._get_path('user',
                                                      'blob_id',
                                                      'trash') + '.flags')
