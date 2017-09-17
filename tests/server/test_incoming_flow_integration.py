# -*- coding: utf-8 -*-
# test_incoming_flow_integration.py
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
Integration tests for the complete flow of IncomingBox feature
"""
import pytest
from uuid import uuid4
from twisted.trial import unittest
from twisted.web.server import Site
from twisted.internet import reactor
from twisted.internet import defer
from twisted.web.resource import Resource
from zope.interface import implementer

from leap.soledad.client.incoming import IncomingBoxProcessingLoop
from leap.soledad.client.incoming import IncomingBox
from leap.soledad.server import _blobs as server_blobs
from leap.soledad.client._db.blobs import BlobManager
from leap.soledad.server._incoming import IncomingResource
from leap.soledad.server._blobs import BlobsServerState
from leap.soledad.client import interfaces


@implementer(interfaces.IIncomingBoxConsumer)
class GoodConsumer(object):
    def __init__(self):
        self.name = 'GoodConsumer'
        self.processed, self.saved = [], []

    def process(self, item, item_id, encrypted=True):
        self.processed.append(item_id)
        return defer.succeed([item_id])

    def save(self, parts, item_id):
        self.saved.append(item_id)
        return defer.succeed(None)


class IncomingFlowIntegrationTestCase(unittest.TestCase):

    def setUp(self):
        root = Resource()
        state = BlobsServerState('filesystem', blobs_path=self.tempdir)
        incoming_resource = IncomingResource(state)
        blobs_resource = server_blobs.BlobsResource("filesystem", self.tempdir)
        root.putChild('blobs', blobs_resource)
        root.putChild('incoming', incoming_resource)
        site = Site(root)
        self.port = reactor.listenTCP(0, site, interface='127.0.0.1')
        self.host = self.port.getHost()
        self.uri = 'http://%s:%s/' % (self.host.host, self.host.port)
        self.blobs_uri = self.uri + 'blobs/'
        self.incoming_uri = self.uri + 'incoming'
        self.user_id = 'user-' + uuid4().hex
        self.secret = 'A' * 96
        self.blob_manager = BlobManager(self.tempdir, self.blobs_uri,
                                        self.secret, self.secret,
                                        self.user_id)
        self.box = IncomingBox(self.blob_manager, 'MX')
        self.loop = IncomingBoxProcessingLoop(self.box)
        # FIXME: We use blob_manager client only to avoid DelayedCalls
        # Somehow treq being used here keeps a connection pool open
        self.client = self.blob_manager._client

    def fill(self, messages):
        deferreds = []
        for message_id, message in messages:
            uri = '%s/%s/%s' % (self.incoming_uri, self.user_id, message_id)
            deferreds.append(self.blob_manager._client.put(uri, data=message))
        return defer.gatherResults(deferreds)

    def tearDown(self):
        self.port.stopListening()
        self.blob_manager.close()

    @defer.inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_consume_a_incoming_message(self):
        yield self.fill([('msg1', 'blob')])
        consumer = GoodConsumer()
        self.loop.add_consumer(consumer)
        yield self.loop()
        self.assertIn('msg1', consumer.processed)
