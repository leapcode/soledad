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
from leap.soledad.client._blobs import BlobManager, BlobDoc, FIXED_REV
from leap.soledad.client._blobs import BlobAlreadyExistsError
from io import BytesIO
from mock import Mock
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
            'uuid', 'token', None)
        self.addCleanup(self.manager.close)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_get_inexistent(self):
        self.manager._download_and_decrypt = Mock(return_value=None)
        bad_blob_id = 'inexsistent_id'
        result = yield self.manager.get(bad_blob_id)
        self.assertIsNone(result)
        self.manager._download_and_decrypt.assert_called_once_with(bad_blob_id)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_get_from_existing_value(self):
        self.manager._download_and_decrypt = Mock(return_value=None)
        msg = "It's me, M4r10!"
        yield self.manager.local.put('myblob_id', BytesIO(msg),
                                     size=len(msg))
        result = yield self.manager.get('myblob_id')
        self.assertEquals(result.getvalue(), msg)
        self.assertNot(self.manager._download_and_decrypt.called)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_put_stores_on_local_db(self):
        self.manager._encrypt_and_upload = Mock(return_value=None)
        msg = "Hey Joe"
        doc = BlobDoc(BytesIO(msg), blob_id='myblob_id')
        yield self.manager.put(doc, size=len(msg))
        result = yield self.manager.local.get('myblob_id')
        self.assertEquals(result.getvalue(), msg)
        self.assertTrue(self.manager._encrypt_and_upload.called)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_put_then_get_using_real_file_descriptor(self):
        self.manager._encrypt_and_upload = Mock(return_value=None)
        self.manager._download_and_decrypt = Mock(return_value=None)
        msg = "Fuuuuull cycleee! \o/"
        tmpfile = os.tmpfile()
        tmpfile.write(msg)
        tmpfile.seek(0)
        doc = BlobDoc(tmpfile, 'myblob_id')
        yield self.manager.put(doc, size=len(msg))
        result = yield self.manager.get(doc.blob_id)
        self.assertEquals(result.getvalue(), msg)
        self.assertTrue(self.manager._encrypt_and_upload.called)
        self.assertFalse(self.manager._download_and_decrypt.called)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_local_list_blobs(self):
        self.manager._encrypt_and_upload = Mock(return_value=None)
        msg = "1337"
        doc = BlobDoc(BytesIO(msg), 'myblob_id')
        yield self.manager.put(doc, size=len(msg))
        doc2 = BlobDoc(BytesIO(msg), 'myblob_id2')
        yield self.manager.put(doc2, size=len(msg))
        blobs_list = yield self.manager.local_list()

        self.assertEquals(set(['myblob_id', 'myblob_id2']), set(blobs_list))

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_send_missing(self):
        fd = BytesIO('test')
        self.manager._encrypt_and_upload = Mock(return_value=None)
        self.manager.remote_list = Mock(return_value=[])
        yield self.manager.local.put('missing_id', fd, 4)
        yield self.manager.send_missing()

        call_list = self.manager._encrypt_and_upload.call_args_list
        self.assertEquals(1, len(call_list))
        call_blob_id, call_fd = call_list[0][0]
        self.assertEquals('missing_id', call_blob_id)
        self.assertEquals('test', call_fd.getvalue())

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_duplicated_blob_error_on_put(self):
        self.manager._encrypt_and_upload = Mock(return_value=None)
        content = "Blob content"
        doc1 = BlobDoc(BytesIO(content), 'existing_id')
        yield self.manager.put(doc1, len(content))
        doc2 = BlobDoc(BytesIO(content), 'existing_id')
        # reset mock, so we can check that upload wasnt called
        self.manager._encrypt_and_upload = Mock(return_value=None)
        with pytest.raises(BlobAlreadyExistsError):
            yield self.manager.put(doc2, len(content))
        self.assertFalse(self.manager._encrypt_and_upload.called)
