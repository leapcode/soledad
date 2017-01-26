# -*- coding: utf-8 -*-
# test__resource.py
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
Tests for Soledad server main resource.
"""
from twisted.trial import unittest
from twisted.web.test.test_web import DummyRequest
from twisted.web.error import Error
from twisted.web.wsgi import WSGIResource

from leap.soledad.server._resource import SoledadResource
from leap.soledad.server._server_info import ServerInfo
from leap.soledad.server._blobs import BlobsResource
from leap.soledad.server.gzip_middleware import GzipMiddleware


conf_blobs_false = {'soledad-server': {'blobs': False}}


class SoledadResourceTestCase(unittest.TestCase):

    def test_get_root(self):
        conf = {'soledad-server': {'blobs': None}}  # doesn't matter
        resource = SoledadResource(conf)
        path = ''
        request = DummyRequest([])
        child = resource.getChild(path, request)
        self.assertIsInstance(child, ServerInfo)

    def test_get_blobs_enabled(self):
        conf = {'soledad-server': {'blobs': True}}
        resource = SoledadResource(conf)
        path = 'blobs'
        request = DummyRequest([])
        child = resource.getChild(path, request)
        self.assertIsInstance(child, BlobsResource)

    def test_get_blobs_disabled(self):
        conf = {'soledad-server': {'blobs': False}}
        resource = SoledadResource(conf)
        path = 'blobs'
        request = DummyRequest([])
        with self.assertRaises(Error):
            resource.getChild(path, request)

    def test_get_sync(self):
        conf = {'soledad-server': {'blobs': None}}  # doesn't matter
        resource = SoledadResource(conf)
        path = 'sync'  # if not 'blobs' or '', should be routed to sync
        request = DummyRequest([])
        request.prepath = ['user-db']
        child = resource.getChild(path, request)
        self.assertIsInstance(child, WSGIResource)
        self.assertIsInstance(child._application, GzipMiddleware)
