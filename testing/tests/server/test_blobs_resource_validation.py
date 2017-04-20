# -*- coding: utf-8 -*-
# test_blobs_resource_validation.py
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
Tests for invalid user or blob_id on blobs resource
"""
import pytest
from twisted.trial import unittest
from twisted.web.test.test_web import DummyRequest
from leap.soledad.server import _blobs as server_blobs


class BlobServerTestCase(unittest.TestCase):

    @pytest.mark.usefixtures("method_tmpdir")
    def setUp(self):
        self.resource = server_blobs.BlobsResource(self.tempdir)

    @pytest.mark.usefixtures("method_tmpdir")
    def test_valid_arguments(self):
        request = DummyRequest(['v4l1d-us3r', 'v4l1d-bl0b-1d'])
        self.assertTrue(self.resource._validate(request))

    @pytest.mark.usefixtures("method_tmpdir")
    def test_invalid_user_get(self):
        request = DummyRequest(['invalid user', 'valid-blob-id'])
        request.path = '/blobs/'
        with pytest.raises(Exception):
            self.resource.render_GET(request)

    @pytest.mark.usefixtures("method_tmpdir")
    def test_invalid_user_put(self):
        request = DummyRequest(['invalid user', 'valid-blob-id'])
        request.path = '/blobs/'
        with pytest.raises(Exception):
            self.resource.render_PUT(request)

    @pytest.mark.usefixtures("method_tmpdir")
    def test_invalid_blob_id_get(self):
        request = DummyRequest(['valid-user', 'invalid blob id'])
        request.path = '/blobs/'
        with pytest.raises(Exception):
            self.resource.render_GET(request)

    @pytest.mark.usefixtures("method_tmpdir")
    def test_invalid_blob_id_put(self):
        request = DummyRequest(['valid-user', 'invalid blob id'])
        request.path = '/blobs/'
        with pytest.raises(Exception):
            self.resource.render_PUT(request)
