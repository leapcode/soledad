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
Integration tests for blobs server
"""
import pytest
from io import BytesIO
from twisted.trial import unittest
from twisted.web.server import Site
from twisted.internet import reactor
from twisted.internet import defer
from leap.soledad.server import _blobs as server_blobs
from leap.soledad.client._blobs import BlobManager


class BlobServerTestCase(unittest.TestCase):

    def setUp(self):
        root = server_blobs.BlobsResource(self.tempdir)
        site = Site(root)
        self.port = reactor.listenTCP(0, site, interface='127.0.0.1')
        self.host = self.port.getHost()
        self.uri = 'http://%s:%s/' % (self.host.host, self.host.port)
        self.secret = 'A' * 96

    def tearDown(self):
        self.port.stopListening()

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_upload(self):
        manager = BlobManager('', self.uri, self.secret,
                              self.secret, 'user')
        fd = BytesIO("save me")
        yield manager._encrypt_and_upload('blob_id', 'mydoc', '1', fd)
        blob, size = yield manager._download_and_decrypt('blob_id',
                                                         'mydoc', '1')
        assert blob.getvalue() == "save me"
