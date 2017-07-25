# -*- coding: utf-8 -*-
# test_incoming_server.py
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
import json
from io import BytesIO
from uuid import uuid4
from twisted.web.test.test_web import DummyRequest
from twisted.web.server import Site
from twisted.internet import reactor
from twisted.internet import defer
import treq

from leap.soledad.server._incoming import IncomingResource
from leap.soledad.server._blobs import BlobsServerState
from leap.soledad.server._incoming import IncomingFormatter
from leap.soledad.common.crypto import EncryptionSchemes
from leap.soledad.common.blobs import Flags
from test_soledad.util import CouchServerStateForTests
from test_soledad.util import CouchDBTestCase


class IncomingOnCouchServerTestCase(CouchDBTestCase):

    def setUp(self):
        self.port = None

    def tearDown(self):
        if self.port:
            self.port.stopListening()

    def prepare(self, backend):
        self.user_id = 'user-' + uuid4().hex
        if backend == 'couch':
            self.state = CouchServerStateForTests(self.couch_url)
            self.state.ensure_database(self.user_id)
        else:
            self.state = BlobsServerState(backend)
        root = IncomingResource(self.state)
        site = Site(root)
        self.port = reactor.listenTCP(0, site, interface='127.0.0.1')
        self.host = self.port.getHost()
        self.uri = 'http://%s:%s/' % (self.host.host, self.host.port)

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_put_incoming_creates_a_document_using_couch(self):
        self.prepare('couch')
        user_id, doc_id = self.user_id, uuid4().hex
        content, scheme = 'Hi', EncryptionSchemes.PUBKEY
        formatter = IncomingFormatter()
        incoming_endpoint = self.uri + '%s/%s' % (user_id, doc_id)
        yield treq.put(incoming_endpoint, BytesIO(content), persistent=False)
        db = self.state.open_database(user_id)

        doc = db.get_doc(doc_id)
        self.assertEquals(doc.content, formatter.format(content, scheme))

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_put_incoming_creates_a_blob_using_filesystem(self):
        self.prepare('filesystem')
        user_id, doc_id = self.user_id, uuid4().hex
        content = 'Hi'
        formatter = IncomingFormatter()
        incoming_endpoint = self.uri + '%s/%s' % (user_id, doc_id)
        yield treq.put(incoming_endpoint, BytesIO(content), persistent=False)

        db = self.state.open_database(user_id)
        request = DummyRequest([user_id, doc_id])
        yield db.read_blob(user_id, doc_id, request, 'MX')
        flags = db.get_flags(user_id, doc_id, request, 'MX')
        flags = json.loads(flags)
        expected = formatter.preamble(content, doc_id) + ' ' + content
        self.assertEquals(expected, request.written[0])
        self.assertIn(Flags.PENDING, flags)
