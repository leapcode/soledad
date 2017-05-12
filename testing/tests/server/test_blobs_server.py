# -*- coding: utf-8 -*-
# test_blobs_server.py
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
Integration tests for blobs server
"""
import pytest
from io import BytesIO
from twisted.trial import unittest
from twisted.web.server import Site
from twisted.internet import reactor
from twisted.internet import defer
from treq._utils import set_global_pool

from leap.soledad.server import _blobs as server_blobs
from leap.soledad.client._db.blobs import BlobManager
from leap.soledad.client._db.blobs import BlobAlreadyExistsError


class BlobServerTestCase(unittest.TestCase):

    def setUp(self):
        root = server_blobs.BlobsResource("filesystem", self.tempdir)
        site = Site(root)
        self.port = reactor.listenTCP(0, site, interface='127.0.0.1')
        self.host = self.port.getHost()
        self.uri = 'http://%s:%s/' % (self.host.host, self.host.port)
        self.secret = 'A' * 96
        set_global_pool(None)

    def tearDown(self):
        self.port.stopListening()

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_upload_download(self):
        manager = BlobManager('', self.uri, self.secret,
                              self.secret, 'user')
        fd = BytesIO("save me")
        yield manager._encrypt_and_upload('blob_id', fd)
        blob, size = yield manager._download_and_decrypt('blob_id')
        self.assertEquals(blob.getvalue(), "save me")

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_upload_changes_remote_list(self):
        manager = BlobManager('', self.uri, self.secret,
                              self.secret, 'user')
        yield manager._encrypt_and_upload('blob_id1', BytesIO("1"))
        yield manager._encrypt_and_upload('blob_id2', BytesIO("2"))
        blobs_list = yield manager.remote_list()
        self.assertEquals(set(['blob_id1', 'blob_id2']), set(blobs_list))

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_upload_deny_duplicates(self):
        manager = BlobManager('', self.uri, self.secret,
                              self.secret, 'user')
        fd = BytesIO("save me")
        yield manager._encrypt_and_upload('blob_id', fd)
        fd = BytesIO("save me")
        with pytest.raises(BlobAlreadyExistsError):
            yield manager._encrypt_and_upload('blob_id', fd)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_send_missing(self):
        manager = BlobManager(self.tempdir, self.uri, self.secret,
                              self.secret, 'user')
        self.addCleanup(manager.close)
        blob_id = 'local_only_blob_id'
        yield manager.local.put(blob_id, BytesIO("X"), size=1)
        yield manager.send_missing()
        result = yield manager._download_and_decrypt(blob_id)
        self.assertIsNotNone(result)
        self.assertEquals(result[0].getvalue(), "X")

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_fetch_missing(self):
        manager = BlobManager(self.tempdir, self.uri, self.secret,
                              self.secret, 'user')
        self.addCleanup(manager.close)
        blob_id = 'remote_only_blob_id'
        yield manager._encrypt_and_upload(blob_id, BytesIO("X"))
        yield manager.fetch_missing()
        result = yield manager.local.get(blob_id)
        self.assertIsNotNone(result)
        self.assertEquals(result.getvalue(), "X")

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_upload_then_delete_updates_list(self):
        manager = BlobManager('', self.uri, self.secret,
                              self.secret, 'user')
        yield manager._encrypt_and_upload('blob_id1', BytesIO("1"))
        yield manager._encrypt_and_upload('blob_id2', BytesIO("2"))
        yield manager._delete_from_remote('blob_id1')
        blobs_list = yield manager.remote_list()
        self.assertEquals(set(['blob_id2']), set(blobs_list))
