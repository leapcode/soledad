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
from twisted.web.client import FileBodyProducer
from leap.common.files import mkdir_p
from leap.soledad.server import _blobs
from mock import Mock
import mock
import os
import base64
import io
import pytest


class FilesystemBackendTestCase(unittest.TestCase):

    @pytest.mark.usefixtures("method_tmpdir")
    @defer.inlineCallbacks
    def test_get_tag(self):
        expected_tag = base64.urlsafe_b64encode('B' * 16)
        backend = _blobs.FilesystemBlobsBackend(blobs_path=self.tempdir)
        # write a blob...
        path = backend._get_path('user', 'blob_id', '')
        mkdir_p(os.path.split(path)[0])
        with open(path, "w") as f:
            f.write('A' * 40 + 'B' * 16)
        # ...and get its tag
        tag = yield backend.get_tag('user', 'blob_id')
        self.assertEquals(expected_tag, tag)

    @pytest.mark.usefixtures("method_tmpdir")
    @defer.inlineCallbacks
    def test_get_blob_size(self):
        # get a backend
        backend = _blobs.FilesystemBlobsBackend(blobs_path=self.tempdir)
        # write a blob with size=10
        path = backend._get_path('user', 'blob_id', '')
        mkdir_p(os.path.split(path)[0])
        with open(path, "w") as f:
            f.write("0123456789")
        # check it's size
        size = yield backend.get_blob_size('user', 'blob_id', '')
        self.assertEquals(10, size)

    @pytest.mark.usefixtures("method_tmpdir")
    @mock.patch('leap.soledad.server._blobs.open')
    @mock.patch('leap.soledad.server._blobs.FilesystemBlobsBackend._get_path')
    @defer.inlineCallbacks
    def test_read_blob(self, get_path, open):
        get_path.return_value = 'path'
        open.return_value = io.BytesIO('content')
        backend = _blobs.FilesystemBlobsBackend(blobs_path=self.tempdir)
        consumer = Mock()
        yield backend.read_blob('user', 'blob_id', consumer)
        consumer.write.assert_called_with('content')
        get_path.assert_called_once_with('user', 'blob_id', '')

    @pytest.mark.usefixtures("method_tmpdir")
    @mock.patch.object(os.path, 'isfile')
    @mock.patch.object(_blobs.FilesystemBlobsBackend, '_get_path',
                       Mock(return_value='path'))
    @defer.inlineCallbacks
    def test_cannot_overwrite(self, isfile):
        isfile.return_value = True
        backend = _blobs.FilesystemBlobsBackend(blobs_path=self.tempdir)
        with pytest.raises(_blobs.BlobExists):
            producer = Mock()
            yield backend.write_blob('user', 'blob_id', producer)

    @pytest.mark.usefixtures("method_tmpdir")
    @mock.patch.object(os.path, 'isfile')
    @defer.inlineCallbacks
    def test_write_cannot_exceed_quota(self, isfile):
        isfile.return_value = False
        backend = _blobs.FilesystemBlobsBackend(blobs_path=self.tempdir)
        backend.get_total_storage = lambda x: defer.succeed(100)
        backend.quota = 90
        with pytest.raises(_blobs.QuotaExceeded):
            producer = FileBodyProducer(io.BytesIO('a' * 100))
            yield backend.write_blob('user', 'blob_id', producer)

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
    @defer.inlineCallbacks
    def test_list_blobs(self, walk_mock):
        backend = _blobs.FilesystemBlobsBackend(blobs_path=self.tempdir)
        _ = None
        walk_mock.return_value = [('', _, ['blob_0']), ('', _, ['blob_1'])]
        result = yield backend.list_blobs('user')
        self.assertEquals(result, ['blob_0', 'blob_1'])

    @pytest.mark.usefixtures("method_tmpdir")
    @mock.patch('leap.soledad.server._blobs.os.walk')
    @defer.inlineCallbacks
    def test_list_blobs_limited_by_namespace(self, walk_mock):
        backend = _blobs.FilesystemBlobsBackend(self.tempdir)
        _ = None
        walk_mock.return_value = [('', _, ['blob_0']), ('', _, ['blob_1'])]
        result = yield backend.list_blobs('user', namespace='incoming')
        self.assertEquals(result, ['blob_0', 'blob_1'])
        target_dir = os.path.join(self.tempdir, 'user', 'incoming')
        walk_mock.assert_called_once_with(target_dir)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_path_validation_on_read_blob(self):
        blobs_path, producer = self.tempdir, Mock()
        backend = _blobs.FilesystemBlobsBackend(blobs_path=blobs_path)
        with pytest.raises(Exception):
            yield backend.read_blob('..', '..', producer)
        with pytest.raises(Exception):
            yield backend.read_blob('user', '../../../', producer)
        with pytest.raises(Exception):
            yield backend.read_blob('../../../', 'blob_id', producer)
        with pytest.raises(Exception):
            yield backend.read_blob('user', 'blob_id', producer,
                                    namespace='..')

    @pytest.mark.usefixtures("method_tmpdir")
    @defer.inlineCallbacks
    def test_path_validation_on_write_blob(self):
        blobs_path, producer = self.tempdir, Mock()
        backend = _blobs.FilesystemBlobsBackend(blobs_path=blobs_path)
        with pytest.raises(Exception):
            yield backend.write_blob('..', '..', producer)
        with pytest.raises(Exception):
            yield backend.write_blob('user', '../../../', producer)
        with pytest.raises(Exception):
            yield backend.write_blob('../../../', 'id1', producer)
        with pytest.raises(Exception):
            yield backend.write_blob('user', 'id2', producer, namespace='..')

    @pytest.mark.usefixtures("method_tmpdir")
    @mock.patch('leap.soledad.server._blobs.os.unlink')
    @defer.inlineCallbacks
    def test_delete_blob(self, unlink_mock):
        backend = _blobs.FilesystemBlobsBackend(blobs_path=self.tempdir)
        # write a blob...
        path = backend._get_path('user', 'blob_id', '')
        mkdir_p(os.path.split(path)[0])
        with open(path, "w") as f:
            f.write("bl0b")
        # ...and delete it
        yield backend.delete_blob('user', 'blob_id')
        unlink_mock.assert_any_call(backend._get_path('user',
                                                      'blob_id'))
        unlink_mock.assert_any_call(backend._get_path('user',
                                                      'blob_id') + '.flags')

    @pytest.mark.usefixtures("method_tmpdir")
    @mock.patch('leap.soledad.server._blobs.os.unlink')
    @defer.inlineCallbacks
    def test_delete_blob_custom_namespace(self, unlink_mock):
        backend = _blobs.FilesystemBlobsBackend(blobs_path=self.tempdir)
        # write a blob...
        path = backend._get_path('user', 'blob_id', 'trash')
        mkdir_p(os.path.split(path)[0])
        with open(path, "w") as f:
            f.write("bl0b")
        # ...and delete it
        yield backend.delete_blob('user', 'blob_id', namespace='trash')
        unlink_mock.assert_any_call(backend._get_path('user',
                                                      'blob_id',
                                                      'trash'))
        unlink_mock.assert_any_call(backend._get_path('user',
                                                      'blob_id',
                                                      'trash') + '.flags')

    @pytest.mark.usefixtures("method_tmpdir")
    @defer.inlineCallbacks
    def test_write_blob_using_namespace(self):
        backend = _blobs.FilesystemBlobsBackend(blobs_path=self.tempdir)
        producer = FileBodyProducer(io.BytesIO('content'))
        yield backend.write_blob('user', 'blob_id', producer,
                                 namespace='custom')
        default = yield backend.list_blobs('user')
        custom = yield backend.list_blobs('user', namespace='custom')
        self.assertEquals([], default)
        self.assertEquals(['blob_id'], custom)

    @pytest.mark.usefixtures("method_tmpdir")
    @defer.inlineCallbacks
    def test_count(self):
        backend = _blobs.FilesystemBlobsBackend(blobs_path=self.tempdir)
        content = 'blah'

        ids = range(5)

        def _write(namespace=''):
            producer = FileBodyProducer(io.BytesIO(content))
            d = backend.write_blob('user', str(ids.pop()), producer,
                                   namespace=namespace)
            return d

        yield _write()
        yield _write()
        yield _write()

        count = yield backend.count('user')
        self.assertEqual(3, count)

        yield _write(namespace='xfiles')
        yield _write(namespace='xfiles')

        count = yield backend.count('user', namespace='xfiles')
        self.assertEqual(2, count)
