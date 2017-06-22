# -*- coding: utf-8 -*-
# test_incoming_resource.py
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
Unit tests for incoming API resource
"""
from twisted.trial import unittest
from twisted.web.test.test_web import DummyRequest
from leap.soledad.server._incoming import IncomingResource
from leap.soledad.server._incoming import IncomingFormatter
from leap.soledad.common.crypto import EncryptionSchemes
from io import BytesIO
from uuid import uuid4
from mock import Mock


class IncomingResourceTestCase(unittest.TestCase):

    def setUp(self):
        self.couchdb = Mock()
        self.backend_factory = Mock()
        self.backend_factory.open_database.return_value = self.couchdb
        self.resource = IncomingResource(self.backend_factory)
        self.user_uuid = uuid4().hex

    def test_save_document(self):
        formatter = IncomingFormatter()
        doc_id, scheme = uuid4().hex, EncryptionSchemes.NONE
        content = 'Incoming content'
        request = DummyRequest([self.user_uuid, doc_id, scheme])
        request.content = BytesIO(content)
        self.resource.render_PUT(request)

        open_database = self.backend_factory.open_database
        open_database.assert_called_once_with(self.user_uuid)
        self.couchdb.put_doc.assert_called_once()
        doc = self.couchdb.put_doc.call_args[0][0]
        self.assertEquals(doc_id, doc.doc_id)
        self.assertEquals(formatter.format(content, scheme), doc.content)
