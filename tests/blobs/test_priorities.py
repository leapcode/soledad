# -*- coding: utf-8 -*-
# test_priorities.py
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
Tests for transfer priorities.
"""
import pytest

from io import BytesIO
from mock import Mock
from twisted.internet import defer
from twisted.trial import unittest
from uuid import uuid4

from leap.soledad.client._db.blobs import BlobManager
from leap.soledad.client._db.blobs import Priority
from leap.soledad.client._db.blobs import SyncStatus
from leap.soledad.client._document import BlobDoc


class BlobPrioritiesTests(unittest.TestCase):

    def setUp(self):
        self.cleartext = BytesIO('patriarchy is opression')
        self.secret = 'A' * 96
        self.manager = BlobManager(
            self.tempdir, '',
            'A' * 32, self.secret,
            uuid4().hex, 'token', None)
        self.addCleanup(self.manager.close)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_get_sets_default_priority(self):
        self.manager._download_and_decrypt = Mock(return_value=None)
        missing_blob_id = uuid4().hex
        result = yield self.manager.get(missing_blob_id)
        self.assertIsNone(result)
        priority = yield self.manager._get_priority(missing_blob_id)
        self.assertEqual(Priority.DEFAULT, priority)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_get_sets_priority(self):
        self.manager._download_and_decrypt = Mock(return_value=None)
        missing_blob_id = uuid4().hex
        urgent = 'urgent'
        result = yield self.manager.get(missing_blob_id, priority=urgent)
        self.assertIsNone(result)
        priority = yield self.manager._get_priority(missing_blob_id)
        self.assertEqual(Priority.URGENT, priority)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_put_sets_default_priority(self):
        upload_failure = defer.fail(Exception())
        self.manager._encrypt_and_upload = Mock(return_value=upload_failure)
        content, blob_id = "Blob content", uuid4().hex
        doc1 = BlobDoc(BytesIO(content), blob_id)
        with pytest.raises(Exception):
            yield self.manager.put(doc1, len(content))
        priority = yield self.manager._get_priority(blob_id)
        self.assertEqual(Priority.DEFAULT, priority)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_put_sets_priority(self):
        upload_failure = defer.fail(Exception())
        self.manager._encrypt_and_upload = Mock(return_value=upload_failure)
        content, blob_id = "Blob content", uuid4().hex
        doc1 = BlobDoc(BytesIO(content), blob_id)
        with pytest.raises(Exception):
            yield self.manager.put(doc1, len(content), priority='urgent')
        priority = yield self.manager._get_priority(blob_id)
        self.assertEqual(Priority.URGENT, priority)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_set_priority_sets_priority(self):
        self.manager._download_and_decrypt = Mock(return_value=None)
        missing_blob_id = uuid4().hex
        result = yield self.manager.get(missing_blob_id)
        self.assertIsNone(result)
        urgent = 'urgent'
        yield self.manager._set_priority(missing_blob_id, urgent)
        priority = yield self.manager._get_priority(missing_blob_id)
        self.assertEqual(Priority.URGENT, priority)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_local_list_status_orders_by_priority(self):
        self.manager._download_and_decrypt = Mock(return_value=None)

        def _get(priority):
            missing_blob_id = uuid4().hex
            d = self.manager.get(missing_blob_id, priority=priority)
            d.addCallback(lambda _: missing_blob_id)
            return d

        # get some blobs in arbitrary order
        low = yield _get('low')
        high = yield _get('high')
        medium = yield _get('medium')
        urgent = yield _get('urgent')

        # make sure they are ordered by priority
        status = SyncStatus.PENDING_DOWNLOAD
        pending = yield self.manager.local_list_status(status)
        self.assertEqual([urgent, high, medium, low], pending)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_refresh_sync_status_from_server_saves_default_priorities(self):
        remote_ids = [uuid4().hex for _ in range(10)]
        self.manager.remote_list = Mock(return_value=defer.succeed(remote_ids))
        yield self.manager.refresh_sync_status_from_server()
        for blob_id in remote_ids:
            priority = yield self.manager._get_priority(blob_id)
            self.assertEquals(Priority.DEFAULT, priority)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_fetch_missing_fetches_with_priority(self):

        # pretend we have some pending downloads
        status = SyncStatus.PENDING_DOWNLOAD
        update_meth = self.manager.local.update_sync_status
        priorities = [
            ('low', Priority.LOW),
            ('high', Priority.HIGH),
            ('medium', Priority.MEDIUM),
            ('urgent', Priority.URGENT),
        ]
        deferreds = []
        for blob_id, priority in priorities:
            d = update_meth(blob_id, status, priority=priority)
            deferreds.append(d)
        yield defer.gatherResults(deferreds)

        # make sure download "succeeds" so fetching works
        content = 'vegan muffin'
        fd = BytesIO(content)
        size = len(content)
        self.manager._download_and_decrypt = Mock(return_value=(fd, size))
        self.manager.concurrent_transfers_limit = 1

        # this is the operation we are interested in
        yield self.manager.fetch_missing()

        # retrieve the order in which blob transfers were made
        calls = self.manager._download_and_decrypt.mock_calls
        order = map(lambda c: c[1][0], calls)
        self.assertEqual(['urgent', 'high', 'medium', 'low'], order)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_send_missing_sends_with_priority(self):

        # pretend we have some pending uploads
        _send = self.manager._send
        self.manager._send = Mock(return_value=None)
        content = "vegan cake"
        length = len(content)
        priorities = [
            ('low', Priority.LOW),
            ('high', Priority.HIGH),
            ('medium', Priority.MEDIUM),
            ('urgent', Priority.URGENT),
        ]
        deferreds = []
        for blob_id, priority in priorities:
            doc = BlobDoc(BytesIO(content), blob_id)
            d = self.manager.put(doc, length, priority=priority)
            deferreds.append(d)
        yield defer.gatherResults(deferreds)

        # make sure upload "succeeds" so sending works
        self.manager._send = _send
        self.manager._encrypt_and_upload = Mock(return_value=None)

        # this is the operation we are interested in
        self.manager.concurrent_transfers_limit = 1
        yield self.manager.send_missing()

        # retrieve the order in which blob transfers were made
        calls = self.manager._encrypt_and_upload.mock_calls
        order = map(lambda c: c[1][0], calls)
        self.assertEqual(['urgent', 'high', 'medium', 'low'], order)
