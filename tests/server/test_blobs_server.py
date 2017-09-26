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
import os
import pytest
from uuid import uuid4
from io import BytesIO
from twisted.trial import unittest
from twisted.web.server import Site
from twisted.internet import reactor
from twisted.internet import defer
from treq._utils import set_global_pool

from leap.soledad.common.blobs import Flags
from leap.soledad.server import _blobs as server_blobs
from leap.soledad.client._db.blobs import BlobManager
from leap.soledad.client._db.blobs import BlobAlreadyExistsError
from leap.soledad.client._db.blobs import InvalidFlagsError
from leap.soledad.client._db.blobs import SoledadError
from leap.soledad.client._db.blobs import SyncStatus
from leap.soledad.client._db import blobs as client_blobs
from leap.soledad.client._crypto import InvalidBlob


def sleep(x):
    d = defer.Deferred()
    reactor.callLater(x, d.callback, None)
    return d


class BlobServerTestCase(unittest.TestCase):

    def setUp(self):
        client_blobs.MAX_WAIT = 0.1
        root = server_blobs.BlobsResource("filesystem", self.tempdir)
        self.site = Site(root)
        self.port = reactor.listenTCP(0, self.site, interface='127.0.0.1')
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
                              self.secret, uuid4().hex)
        fd = BytesIO("save me")
        yield manager._encrypt_and_upload('blob_id', fd)
        blob, size = yield manager._download_and_decrypt('blob_id')
        self.assertEquals(blob.getvalue(), "save me")

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_set_get_flags(self):
        manager = BlobManager('', self.uri, self.secret,
                              self.secret, uuid4().hex)
        fd = BytesIO("flag me")
        yield manager._encrypt_and_upload('blob_id', fd)
        yield manager.set_flags('blob_id', [Flags.PROCESSING])
        flags = yield manager.get_flags('blob_id')
        self.assertEquals([Flags.PROCESSING], flags)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_set_flags_raises_if_no_blob_found(self):
        manager = BlobManager('', self.uri, self.secret,
                              self.secret, uuid4().hex)
        with pytest.raises(SoledadError):
            yield manager.set_flags('missing_id', [Flags.PENDING])

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_get_flags_raises_if_no_blob_found(self):
        manager = BlobManager('', self.uri, self.secret,
                              self.secret, uuid4().hex)
        with pytest.raises(SoledadError):
            yield manager.get_flags('missing_id')

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_list_filter_flag(self):
        manager = BlobManager('', self.uri, self.secret,
                              self.secret, uuid4().hex)
        fd = BytesIO("flag me")
        yield manager._encrypt_and_upload('blob_id', fd)
        yield manager.set_flags('blob_id', [Flags.PROCESSING])
        blobs_list = yield manager.remote_list(filter_flag=Flags.PENDING)
        self.assertEquals([], blobs_list)
        blobs_list = yield manager.remote_list(filter_flag=Flags.PROCESSING)
        self.assertEquals(['blob_id'], blobs_list)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_list_filter_flag_order_by_date(self):
        manager = BlobManager('', self.uri, self.secret,
                              self.secret, uuid4().hex)
        yield manager._encrypt_and_upload('blob_id1', BytesIO("x"))
        yield manager._encrypt_and_upload('blob_id2', BytesIO("x"))
        yield manager._encrypt_and_upload('blob_id3', BytesIO("x"))
        yield manager.set_flags('blob_id1', [Flags.PROCESSING])
        yield manager.set_flags('blob_id2', [Flags.PROCESSING])
        yield manager.set_flags('blob_id3', [Flags.PROCESSING])
        blobs_list = yield manager.remote_list(filter_flag=Flags.PROCESSING,
                                               order_by='+date')
        expected_list = ['blob_id1', 'blob_id2', 'blob_id3']
        self.assertEquals(expected_list, blobs_list)
        blobs_list = yield manager.remote_list(filter_flag=Flags.PROCESSING,
                                               order_by='-date')
        self.assertEquals(list(reversed(expected_list)), blobs_list)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_cant_set_invalid_flags(self):
        manager = BlobManager('', self.uri, self.secret,
                              self.secret, uuid4().hex)
        fd = BytesIO("flag me")
        yield manager._encrypt_and_upload('blob_id', fd)
        with pytest.raises(InvalidFlagsError):
            yield manager.set_flags('blob_id', ['invalid'])
        flags = yield manager.get_flags('blob_id')
        self.assertEquals([], flags)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_get_empty_flags(self):
        manager = BlobManager('', self.uri, self.secret,
                              self.secret, uuid4().hex)
        fd = BytesIO("flag me")
        yield manager._encrypt_and_upload('blob_id', fd)
        flags = yield manager.get_flags('blob_id')
        self.assertEquals([], flags)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_flags_ignored_by_listing(self):
        manager = BlobManager('', self.uri, self.secret,
                              self.secret, uuid4().hex)
        fd = BytesIO("flag me")
        yield manager._encrypt_and_upload('blob_id', fd)
        yield manager.set_flags('blob_id', [Flags.PROCESSING])
        blobs_list = yield manager.remote_list()
        self.assertEquals(['blob_id'], blobs_list)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_upload_changes_remote_list(self):
        manager = BlobManager('', self.uri, self.secret,
                              self.secret, uuid4().hex)
        yield manager._encrypt_and_upload('blob_id1', BytesIO("1"))
        yield manager._encrypt_and_upload('blob_id2', BytesIO("2"))
        blobs_list = yield manager.remote_list()
        self.assertEquals(set(['blob_id1', 'blob_id2']), set(blobs_list))

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_list_orders_by_date(self):
        user_uid = uuid4().hex
        manager = BlobManager('', self.uri, self.secret,
                              self.secret, user_uid)
        yield manager._encrypt_and_upload('blob_id1', BytesIO("1"))
        yield manager._encrypt_and_upload('blob_id2', BytesIO("2"))
        blobs_list = yield manager.remote_list(order_by='date')
        self.assertEquals(['blob_id1', 'blob_id2'], blobs_list)
        parts = [user_uid, 'default', 'b', 'blo', 'blob_i', 'blob_id1']
        self.__touch(self.tempdir, *parts)
        blobs_list = yield manager.remote_list(order_by='+date')
        self.assertEquals(['blob_id2', 'blob_id1'], blobs_list)
        blobs_list = yield manager.remote_list(order_by='-date')
        self.assertEquals(['blob_id1', 'blob_id2'], blobs_list)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_count(self):
        manager = BlobManager('', self.uri, self.secret,
                              self.secret, uuid4().hex)
        deferreds = []
        for i in range(10):
            deferreds.append(manager._encrypt_and_upload(str(i), BytesIO("1")))
        yield defer.gatherResults(deferreds)

        result = yield manager.count()
        self.assertEquals({"count": len(deferreds)}, result)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_list_restricted_by_namespace(self):
        manager = BlobManager('', self.uri, self.secret,
                              self.secret, uuid4().hex)
        namespace = 'incoming'
        yield manager._encrypt_and_upload('blob_id1', BytesIO("1"),
                                          namespace=namespace)
        yield manager._encrypt_and_upload('blob_id2', BytesIO("2"))
        blobs_list = yield manager.remote_list(namespace=namespace)
        self.assertEquals(['blob_id1'], blobs_list)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_list_default_doesnt_list_other_namespaces(self):
        manager = BlobManager('', self.uri, self.secret,
                              self.secret, uuid4().hex)
        namespace = 'incoming'
        yield manager._encrypt_and_upload('blob_id1', BytesIO("1"),
                                          namespace=namespace)
        yield manager._encrypt_and_upload('blob_id2', BytesIO("2"))
        blobs_list = yield manager.remote_list()
        self.assertEquals(['blob_id2'], blobs_list)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_download_from_namespace(self):
        manager = BlobManager('', self.uri, self.secret,
                              self.secret, uuid4().hex)
        namespace, blob_id, content = 'incoming', 'blob_id1', 'test'
        yield manager._encrypt_and_upload(blob_id, BytesIO(content),
                                          namespace=namespace)
        got_blob = yield manager._download_and_decrypt(blob_id, namespace)
        self.assertEquals(content, got_blob[0].getvalue())

    def __touch(self, *args):
        path = os.path.join(*args)
        with open(path, 'a'):
            os.utime(path, None)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_upload_deny_duplicates(self):
        manager = BlobManager('', self.uri, self.secret,
                              self.secret, uuid4().hex)
        fd = BytesIO("save me")
        yield manager._encrypt_and_upload('blob_id', fd)
        fd = BytesIO("save me")
        with pytest.raises(BlobAlreadyExistsError):
            yield manager._encrypt_and_upload('blob_id', fd)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_send_missing(self):
        manager = BlobManager(self.tempdir, self.uri, self.secret,
                              self.secret, uuid4().hex)
        self.addCleanup(manager.close)
        blob_id = 'local_only_blob_id'
        yield manager.local.put(blob_id, BytesIO("X"), size=1)
        yield manager.send_missing()
        result = yield manager._download_and_decrypt(blob_id)
        self.assertIsNotNone(result)
        self.assertEquals(result[0].getvalue(), "X")

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_send_missing_retry(self):
        manager = BlobManager(self.tempdir, self.uri, self.secret,
                              self.secret, uuid4().hex)
        self.addCleanup(manager.close)
        blob_id = 'remote_only_blob_id'
        yield manager.local.put(blob_id, BytesIO("X"), size=1)
        yield self.port.stopListening()

        d = manager.send_missing()
        yield sleep(0.1)
        self.port = reactor.listenTCP(
            self.host.port, self.site, interface='127.0.0.1')
        yield d
        result = yield manager._download_and_decrypt(blob_id)
        self.assertIsNotNone(result)
        self.assertEquals(result[0].getvalue(), "X")

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_sync_fetch_missing(self):
        manager = BlobManager(self.tempdir, self.uri, self.secret,
                              self.secret, uuid4().hex)
        self.addCleanup(manager.close)
        blob_id = 'remote_only_blob_id'
        yield manager._encrypt_and_upload(blob_id, BytesIO("X"))
        yield manager.sync()
        result = yield manager.local.get(blob_id)
        self.assertIsNotNone(result)
        self.assertEquals(result.getvalue(), "X")

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_sync_fetch_missing_retry(self):
        manager = BlobManager(self.tempdir, self.uri, self.secret,
                              self.secret, uuid4().hex)
        self.addCleanup(manager.close)
        blob_id = 'remote_only_blob_id'
        yield manager._encrypt_and_upload(blob_id, BytesIO("X"))
        yield manager.refresh_sync_status_from_server()
        yield self.port.stopListening()

        d = manager.fetch_missing()
        yield sleep(0.1)
        self.port = reactor.listenTCP(
            self.host.port, self.site, interface='127.0.0.1')
        yield d
        result = yield manager.local.get(blob_id)
        self.assertIsNotNone(result)
        self.assertEquals(result.getvalue(), "X")

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_download_corrupted_tag_marks_blob_as_failed(self):
        user_id = uuid4().hex
        manager = BlobManager(self.tempdir, self.uri, self.secret,
                              self.secret, user_id)
        self.addCleanup(manager.close)
        blob_id = 'corrupted'
        yield manager._encrypt_and_upload(blob_id, BytesIO("corrupted"))
        parts = ['default'] + [blob_id[0], blob_id[0:3], blob_id[0:6]]
        parts += [blob_id]
        corrupted_blob_path = os.path.join(self.tempdir, user_id, *parts)
        with open(corrupted_blob_path, 'r+b') as corrupted_blob:
            # Corrupt the tag (last 16 bytes)
            corrupted_blob.seek(-16, 2)
            corrupted_blob.write('x' * 16)
        with pytest.raises(InvalidBlob):
            yield manager.sync()
        status, retries = yield manager.local.get_sync_status(blob_id)
        self.assertEquals(status, SyncStatus.FAILED_DOWNLOAD)
        self.assertEquals(retries, 3)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_upload_then_delete_updates_list(self):
        manager = BlobManager('', self.uri, self.secret,
                              self.secret, uuid4().hex)
        yield manager._encrypt_and_upload('blob_id1', BytesIO("1"))
        yield manager._encrypt_and_upload('blob_id2', BytesIO("2"))
        yield manager._delete_from_remote('blob_id1')
        blobs_list = yield manager.remote_list()
        self.assertEquals(set(['blob_id2']), set(blobs_list))

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_upload_then_delete_updates_list_using_namespace(self):
        manager = BlobManager('', self.uri, self.secret,
                              self.secret, uuid4().hex)
        namespace = 'special_archives'
        yield manager._encrypt_and_upload('blob_id1', BytesIO("1"),
                                          namespace=namespace)
        yield manager._encrypt_and_upload('blob_id2', BytesIO("2"),
                                          namespace=namespace)
        yield manager._delete_from_remote('blob_id1', namespace=namespace)
        blobs_list = yield manager.remote_list(namespace=namespace)
        self.assertEquals(set(['blob_id2']), set(blobs_list))

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_get_fails_if_no_blob_found(self):
        manager = BlobManager(self.tempdir, self.uri, self.secret,
                              self.secret, uuid4().hex)
        self.addCleanup(manager.close)
        with pytest.raises(SoledadError):
            yield manager.get('missing_id')

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_delete_fails_if_no_blob_found(self):
        manager = BlobManager(self.tempdir, self.uri, self.secret,
                              self.secret, uuid4().hex)
        self.addCleanup(manager.close)
        with pytest.raises(SoledadError):
            yield manager.delete('missing_id')
