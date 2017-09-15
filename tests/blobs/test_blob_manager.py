# -*- coding: utf-8 -*-
# test_local_backend.py
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
Tests for BlobManager.
"""
from twisted.trial import unittest
from twisted.internet import defer
from leap.soledad.client._db.blobs import BlobManager, BlobDoc, FIXED_REV
from leap.soledad.client._db.blobs import BlobAlreadyExistsError
from leap.soledad.client._db.blobs import SyncStatus
from io import BytesIO
from mock import Mock
from uuid import uuid4
import pytest
import os


class BlobManagerTestCase(unittest.TestCase):

    class doc_info:
        doc_id = 'D-deadbeef'
        rev = FIXED_REV

    def setUp(self):
        self.cleartext = BytesIO('rosa de foc')
        self.secret = 'A' * 96
        self.manager = BlobManager(
            self.tempdir, '',
            'A' * 32, self.secret,
            uuid4().hex, 'token', None)
        self.addCleanup(self.manager.close)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_get_missing(self):
        self.manager._download_and_decrypt = Mock(return_value=None)
        missing_blob_id = uuid4().hex
        result = yield self.manager.get(missing_blob_id)
        self.assertIsNone(result)
        args = missing_blob_id, ''
        self.manager._download_and_decrypt.assert_called_once_with(*args)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_get_from_existing_value(self):
        self.manager._download_and_decrypt = Mock(return_value=None)
        msg, blob_id = "It's me, M4r10!", uuid4().hex
        yield self.manager.local.put(blob_id, BytesIO(msg),
                                     size=len(msg))
        result = yield self.manager.get(blob_id)
        self.assertEquals(result.getvalue(), msg)
        self.assertNot(self.manager._download_and_decrypt.called)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_put_stores_on_local_db(self):
        self.manager._encrypt_and_upload = Mock(return_value=None)
        msg, blob_id = "Hey Joe", uuid4().hex
        doc = BlobDoc(BytesIO(msg), blob_id=blob_id)
        yield self.manager.put(doc, size=len(msg))
        result = yield self.manager.local.get(blob_id)
        self.assertEquals(result.getvalue(), msg)
        self.assertTrue(self.manager._encrypt_and_upload.called)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_put_then_get_using_real_file_descriptor(self):
        self.manager._encrypt_and_upload = Mock(return_value=None)
        self.manager._download_and_decrypt = Mock(return_value=None)
        msg, blob_id = "Fuuuuull cycleee! \o/", uuid4().hex
        tmpfile = os.tmpfile()
        tmpfile.write(msg)
        tmpfile.seek(0)
        doc = BlobDoc(tmpfile, blob_id)
        yield self.manager.put(doc, size=len(msg))
        result = yield self.manager.get(doc.blob_id)
        self.assertEquals(result.getvalue(), msg)
        self.assertTrue(self.manager._encrypt_and_upload.called)
        self.assertFalse(self.manager._download_and_decrypt.called)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_local_list_blobs(self):
        self.manager._encrypt_and_upload = Mock(return_value=None)
        msg, blob_id1, blob_id2 = "1337", uuid4().hex, uuid4().hex
        doc = BlobDoc(BytesIO(msg), blob_id1)
        yield self.manager.put(doc, size=len(msg))
        doc2 = BlobDoc(BytesIO(msg), blob_id2)
        yield self.manager.put(doc2, size=len(msg))
        blobs_list = yield self.manager.local_list()

        self.assertEquals(set([blob_id1, blob_id2]), set(blobs_list))

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_send_missing(self):
        fd, missing_id = BytesIO('test'), uuid4().hex
        self.manager._encrypt_and_upload = Mock(return_value=None)
        self.manager.remote_list = Mock(return_value=[])
        yield self.manager.local.put(missing_id, fd, 4)
        yield self.manager.send_missing()

        call_list = self.manager._encrypt_and_upload.call_args_list
        self.assertEquals(1, len(call_list))
        call_blob_id, call_fd = call_list[0][0]
        self.assertEquals(missing_id, call_blob_id)
        self.assertEquals('test', call_fd.getvalue())

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_duplicated_blob_error_on_put(self):
        self.manager._encrypt_and_upload = Mock(return_value=None)
        content, existing_id = "Blob content", uuid4().hex
        doc1 = BlobDoc(BytesIO(content), existing_id)
        yield self.manager.put(doc1, len(content))
        doc2 = BlobDoc(BytesIO(content), existing_id)
        self.manager._encrypt_and_upload.reset_mock()
        with pytest.raises(BlobAlreadyExistsError):
            yield self.manager.put(doc2, len(content))
        self.assertFalse(self.manager._encrypt_and_upload.called)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_delete_from_local_and_remote(self):
        self.manager._encrypt_and_upload = Mock(return_value=None)
        self.manager._delete_from_remote = Mock(return_value=None)
        content, blob_id = "Blob content", uuid4().hex
        doc1 = BlobDoc(BytesIO(content), blob_id)
        yield self.manager.put(doc1, len(content))
        yield self.manager.delete(blob_id)
        local_list = yield self.manager.local_list()
        self.assertEquals(0, len(local_list))
        params = {'namespace': ''}
        self.manager._delete_from_remote.assert_called_with(blob_id, **params)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_local_sync_status_pending_upload(self):
        upload_failure = defer.fail(Exception())
        self.manager._encrypt_and_upload = Mock(return_value=upload_failure)
        content, blob_id = "Blob content", uuid4().hex
        doc1 = BlobDoc(BytesIO(content), blob_id)
        with pytest.raises(Exception):
            yield self.manager.put(doc1, len(content))
        pending_upload = SyncStatus.PENDING_UPLOAD
        local_list = yield self.manager.local_list(sync_status=pending_upload)
        self.assertIn(blob_id, local_list)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_upload_retry_limit(self):
        self.manager.remote_list = Mock(return_value=[])
        content, blob_id = "Blob content", uuid4().hex
        doc1 = BlobDoc(BytesIO(content), blob_id)
        with pytest.raises(Exception):
            yield self.manager.put(doc1, len(content))
        for _ in range(self.manager.max_retries + 1):
            with pytest.raises(defer.FirstError):
                yield self.manager.send_missing()
        failed_upload = SyncStatus.FAILED_UPLOAD
        local_list = yield self.manager.local_list(sync_status=failed_upload)
        self.assertIn(blob_id, local_list)
