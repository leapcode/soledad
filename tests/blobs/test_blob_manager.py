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
from leap.soledad.client._document import BlobDoc
from leap.soledad.client._db.blobs import BlobManager, FIXED_REV
from leap.soledad.client._db.blobs import BlobAlreadyExistsError
from leap.soledad.client._db.blobs import SyncStatus
from io import BytesIO
from mock import Mock
from uuid import uuid4
import pytest
import os

# monkey-patch the blobmanager MAX_WAIT time so tests run faster
from leap.soledad.client._db.blobs import sync
sync.MAX_WAIT = 1


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
    def test_put_local_only_doesnt_send_to_server(self):
        self.manager._encrypt_and_upload = Mock(return_value=None)
        msg, blob_id = "Hey Joe", uuid4().hex
        doc = BlobDoc(BytesIO(msg), blob_id=blob_id)
        yield self.manager.put(doc, size=len(msg), local_only=True)
        result = yield self.manager.local.get(blob_id)
        status, _ = yield self.manager.local.get_sync_status(blob_id)
        self.assertEquals(result.getvalue(), msg)
        self.assertEquals(status, SyncStatus.LOCAL_ONLY)
        self.assertFalse(self.manager._encrypt_and_upload.called)

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
        doc1 = BlobDoc(fd, missing_id)
        yield self.manager.put(doc1, 4)
        yield self.manager.send_missing()

        call_list = self.manager._encrypt_and_upload.call_args_list
        self.assertEquals(1, len(call_list))
        call_blob_id, call_fd = call_list[0][0]
        self.assertEquals(missing_id, call_blob_id)
        self.assertEquals('test', call_fd.getvalue())

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_sync_progress(self):
        deferreds = []
        local = self.manager.local
        pending_download = SyncStatus.PENDING_DOWNLOAD
        pending_upload = SyncStatus.PENDING_UPLOAD
        synced = SyncStatus.SYNCED
        for status in [pending_download, pending_upload, synced, synced]:
            deferreds.append(local.update_sync_status(uuid4().hex, status))
        yield defer.gatherResults(deferreds)

        progress = yield self.manager.sync_progress
        self.assertEquals(progress, {
            'PENDING_DOWNLOAD': 1, 'PENDING_UPLOAD': 1, 'SYNCED': 2})

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
    def test_offline_delete_marks_as_pending_download(self):
        deletion_failure = defer.fail(Exception())
        self.manager._encrypt_and_upload = Mock(return_value=None)
        self.manager._delete_from_remote = Mock(return_value=deletion_failure)
        content, blob_id = "Blob content", uuid4().hex
        doc1 = BlobDoc(BytesIO(content), blob_id)
        yield self.manager.put(doc1, len(content))
        with pytest.raises(Exception):
            yield self.manager.delete(blob_id)
        sync_progress = yield self.manager.sync_progress
        expected = {'PENDING_DELETE': 1}
        self.assertEquals(expected, sync_progress)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_online_delete_marks_as_synced(self):
        self.manager._encrypt_and_upload = Mock(return_value=None)
        self.manager._delete_from_remote = Mock(return_value=None)
        content, blob_id = "Blob content", uuid4().hex
        doc1 = BlobDoc(BytesIO(content), blob_id)
        yield self.manager.put(doc1, len(content))
        yield self.manager.delete(blob_id)
        sync_progress = yield self.manager.sync_progress
        expected = {'SYNCED': 1}
        self.assertEquals(expected, sync_progress)

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
        local_list = yield self.manager.local_list_status(pending_upload)
        self.assertIn(blob_id, local_list)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_local_list_doesnt_include_unavailable_blobs(self):
        local = self.manager.local
        unavailable_ids, deferreds = [], []
        for status in SyncStatus.UNAVAILABLE_STATUSES:
            blob_id = uuid4().hex
            deferreds.append(local.update_sync_status(blob_id, status))
            unavailable_ids.append(blob_id)
        available_blob_id = uuid4().hex
        content, length = self.cleartext, len(self.cleartext.getvalue())
        deferreds.append(local.put(available_blob_id, content, length))
        yield defer.gatherResults(deferreds)
        local_list = yield local.list()
        message = 'Unavailable blob showing up on listing!'
        for blob_id in unavailable_ids:
            self.assertNotIn(blob_id, local_list, message)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_get_doesnt_include_unavailable_blobs(self):
        local = self.manager.local
        unavailable_ids, deferreds = [], []
        for status in SyncStatus.UNAVAILABLE_STATUSES:
            blob_id = uuid4().hex
            deferreds.append(local.update_sync_status(blob_id, status))
            unavailable_ids.append(blob_id)
        available_blob_id = uuid4().hex
        content, length = self.cleartext, len(self.cleartext.getvalue())
        deferreds.append(local.put(available_blob_id, content, length))
        yield defer.gatherResults(deferreds)
        message = 'Unavailable blob showing up on GET!'
        for blob_id in unavailable_ids:
            blob = yield local.get(blob_id)
            self.assertFalse(blob, message)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_persist_sync_statuses_listing_from_server(self):
        local = self.manager.local
        remote_ids = [uuid4().hex for _ in range(10)]
        local_ids = [uuid4().hex for _ in range(10)]
        self.manager.remote_list = Mock(return_value=defer.succeed(remote_ids))
        content, pending = self.cleartext, SyncStatus.PENDING_UPLOAD
        length, deferreds = len(content.getvalue()), []
        for blob_id in local_ids:
            d = local.put(blob_id, content, length)
            deferreds.append(d)
            d = local.update_sync_status(blob_id, pending)
            deferreds.append(d)
        yield defer.gatherResults(deferreds)
        yield self.manager.refresh_sync_status_from_server()
        d = self.manager.local_list_status(SyncStatus.PENDING_UPLOAD)
        pending_upload_list = yield d
        d = self.manager.local_list_status(SyncStatus.PENDING_DOWNLOAD)
        pending_download_list = yield d
        self.assertEquals(set(pending_upload_list), set(local_ids))
        self.assertEquals(set(pending_download_list), set(remote_ids))
