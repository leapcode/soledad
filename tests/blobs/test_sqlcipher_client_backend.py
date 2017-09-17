# -*- coding: utf-8 -*-
# test_sqlcipher_client_backend.py
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
Tests for sqlcipher backend on blobs client.
"""
from twisted.trial import unittest
from twisted.internet import defer
from leap.soledad.client._db.blobs import SQLiteBlobBackend
from io import BytesIO
from uuid import uuid4
import pytest


class SQLBackendTestCase(unittest.TestCase):

    def setUp(self):
        self.key = "A" * 96
        self.local = SQLiteBlobBackend(self.tempdir, self.key)
        self.addCleanup(self.local.close)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_get_inexisting(self):
        bad_blob_id = uuid4().hex
        self.assertFalse((yield self.local.exists(bad_blob_id)))
        result = yield self.local.get(bad_blob_id)
        self.assertIsNone(result)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_get_existing(self):
        blob_id = uuid4().hex
        content = "x"
        yield self.local.put(blob_id, BytesIO(content), len(content))
        result = yield self.local.get(blob_id)
        self.assertTrue((yield self.local.exists(blob_id)))
        self.assertEquals(result.getvalue(), content)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_delete(self):
        blob_id1, blob_id2 = uuid4().hex, uuid4().hex
        content = "x"
        yield self.local.put(blob_id1, BytesIO(content), len(content))
        yield self.local.put(blob_id2, BytesIO(content), len(content))
        yield self.local.delete(blob_id1)
        self.assertFalse((yield self.local.exists(blob_id1)))
        self.assertTrue((yield self.local.exists(blob_id2)))

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_list(self):
        blob_ids = [uuid4().hex for _ in range(10)]
        content = "x"
        deferreds = []
        for blob_id in blob_ids:
            deferreds.append(self.local.put(blob_id, BytesIO(content),
                             len(content)))
        yield defer.gatherResults(deferreds)
        result = yield self.local.list()
        self.assertEquals(set(blob_ids), set(result))
