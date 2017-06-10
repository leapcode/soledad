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
Integration tests for incoming API
"""
import pytest
from io import BytesIO
from uuid import uuid4
from twisted.web.server import Site
from twisted.internet import reactor
from twisted.internet import defer
import treq

from leap.soledad.server._incoming import IncomingResource
from leap.soledad.server._incoming import IncomingFormatter
from leap.soledad.common.crypto import EncryptionSchemes
from test_soledad.util import CouchServerStateForTests
from test_soledad.util import CouchDBTestCase


class BlobServerTestCase(CouchDBTestCase):

    def setUp(self):
        self.state = CouchServerStateForTests(self.couch_url)
        root = IncomingResource(self.state)
        site = Site(root)
        self.port = reactor.listenTCP(0, site, interface='127.0.0.1')
        self.host = self.port.getHost()
        self.uri = 'http://%s:%s/' % (self.host.host, self.host.port)
        self.user_id = 'user-' + uuid4().hex
        self.state.ensure_database(self.user_id)

    def tearDown(self):
        self.port.stopListening()

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_put_incoming_creates_a_document(self):
        user_id, doc_id = self.user_id, uuid4().hex
        content, scheme = 'Hi', EncryptionSchemes.NONE
        formatter = IncomingFormatter()
        incoming_endpoint = self.uri + '%s/%s/%s' % (user_id, doc_id, scheme)
        yield treq.put(incoming_endpoint, BytesIO(content), persistent=False)
        db = self.state.open_database(user_id)

        doc = db.get_doc(doc_id)
        self.assertEquals(doc.content, formatter.format(content, scheme))
