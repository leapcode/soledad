# -*- coding: utf-8 -*-
# test__server_info.py
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
Tests for Soledad server information announcement.
"""
import json

from twisted.trial import unittest
from twisted.web.test.test_web import DummyRequest

from leap.soledad.server._server_info import ServerInfo


class ServerInfoTestCase(unittest.TestCase):

    def test_blobs_enabled(self):
        resource = ServerInfo(True)
        response = resource.render(DummyRequest(['']))
        _info = json.loads(response)
        self.assertEquals(_info['blobs'], True)
        self.assertTrue(isinstance(_info['version'], basestring))

    def test_blobs_disabled(self):
        resource = ServerInfo(False)
        response = resource.render(DummyRequest(['']))
        _info = json.loads(response)
        self.assertEquals(_info['blobs'], False)
        self.assertTrue(isinstance(_info['version'], basestring))
