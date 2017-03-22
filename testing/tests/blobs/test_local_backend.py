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
Tests for sqlcipher backend on blobs client.
"""
from twisted.trial import unittest
from twisted.internet import defer
from leap.soledad.client._blobs import BlobManager
from io import BytesIO
from mock import Mock
import pytest


class SQLCipherBlobsClientTestCase(unittest.TestCase):

    class doc_info:
        doc_id = 'D-deadbeef'
        rev = '397932e0c77f45fcb7c3732930e7e9b2:1'

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
        args = ('inexistent_blob_id', 'inexistent_doc_id', 'inexistent_rev')
        result = yield self.manager.get(*args)
        assert result is None
        self.manager._download_and_decrypt.assert_called_once_with(*args)
