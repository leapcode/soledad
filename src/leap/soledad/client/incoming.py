# -*- coding: utf-8 -*-
# incoming.py
# Copyright (C) 2017 LEAP
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
Code to interact with Incoming Box feature.
See: http://soledad.readthedocs.io/en/latest/incoming_box.html
     or docs/incoming_box.rst
"""
import sys
from leap.soledad.common.blobs import Flags
from twisted.logger import Logger
from twisted.internet.task import LoopingCall
from twisted.internet import defer
log = Logger()


class IncomingBoxProcessingLoop:
    """
    Implements the client-side processing flow for Incoming Box feature,
    maintaining a loop that fetches incoming messages from remote replica,
    delivers it to consumers and changes flags as necessary. This is defined at
    "Processing Incoming Messages" section on Incoming Box Specifications:
    http://soledad.readthedocs.io/en/latest/incoming_box.html
    """

    def __init__(self, incoming_box):
        self.incoming_box = incoming_box
        self.consumers = []
        self._loop = LoopingCall(self._process)

    def __call__(self):
        return self._process()

    @property
    def running(self):
        return self._loop.running

    def start(self, interval=30):
        """
        Starts the inner LoopingCall, triggering the loop.
        :param interval: Time between interactions in seconds.
        :type interval: int
        """
        return self._loop.start(interval)

    def stop(self):
        """
        Stops the inner LoopingCall, stopping the loop.
        """
        return self._loop.stop()

    def add_consumer(self, consumer):
        """
        Adds a consumer to the consumers list, so it can be used to process and
        persist incoming box items.
        :param consumer: Consumer implementation
        :type consumer: leap.soledad.client.interfaces.IIncomingBoxConsumer
        """
        self.consumers.append(consumer)

    @defer.inlineCallbacks
    def _process(self):
        pending = yield self.incoming_box.list_pending()
        for item_id in pending:
            item = yield self.incoming_box.fetch_for_processing(item_id)
            if not item:
                log.warn("Couldn't reserve item %s for processing, skipping.")
                continue
            failed = False
            for consumer in self.consumers:
                try:
                    parts = yield consumer.process(item, item_id=item_id)
                except:
                    msg = "Consumer %s failed to process item %s: %s"
                    msg %= (consumer.name, item_id, sys.exc_info()[0])
                    log.error(msg)
                    failed = True
                    continue
                yield self.incoming_box.set_processed(item_id)
                try:
                    yield consumer.save(parts, item_id=item_id)
                except:
                    msg = "Consumer %s failed to save item %s: %s"
                    msg %= (consumer.name, item_id, sys.exc_info()[0])
                    log.error(msg)
                    failed = True
            if failed:
                yield self.incoming_box.set_failed(item_id)
            else:
                yield self.incoming_box.delete(item_id)


class IncomingBox:
    """
    A BlobManager proxy that represents an user's Incoming Box.
    It locks all queries to a namespace and deals with parameters and
    implementation details as defined on specification for client/server
    interactions.
    """

    def __init__(self, blob_manager, namespace):
        self.blob_manager = blob_manager
        self.namespace = namespace

    @defer.inlineCallbacks
    def fetch_for_processing(self, blob_id):
        """
        Try to reserve a blob (by flagging it as PROCESSING) and then fetch it.
        If it is already reserved by another replica, return `None` causing the
        loop to skip this item.
        :param blob_id: Unique identifier of a blob.
        :type blob_id: str
        :return: A deferred that fires when operation finishes.
            It will hold None if reservation fails or a file-like object with
            the requested blob.
        :rtype: Deferred
        """
        try:
            yield self.blob_manager.set_flags(blob_id, [Flags.PROCESSED],
                                              namespace=self.namespace)
        except:
            defer.returnValue(None)
        blob = yield self.blob_manager.get(blob_id, namespace=self.namespace)
        defer.returnValue(blob)

    def list_pending(self):
        """
        Lists blobs sorted by date (older first).
        :return: A deferred that fires with the requested list.
        :rtype: Deferred
        """
        return self.blob_manager.remote_list(namespace=self.namespace,
                                             order_by='+date',
                                             filter_flag=Flags.PENDING)

    def set_processed(self, blob_id):
        """
        Flag a blob with Flags.PROCESSED
        :param blob_id: Unique identifier of a blob.
        :type blob_id: str
        :return: A deferred that fires when operation finishes.
        :rtype: Deferred
        """
        return self.blob_manager.set_flags(blob_id, [Flags.PROCESSED],
                                           namespace=self.namespace)

    def set_failed(self, blob_id):
        """
        Flag a blob with Flags.FAILED
        :param blob_id: Unique identifier of a blob.
        :type blob_id: str
        :return: A deferred that fires when operation finishes.
        :rtype: Deferred
        """
        return self.blob_manager.set_flags(blob_id, [Flags.FAILED],
                                           namespace=self.namespace)

    def delete(self, blob_id):
        """
        Deletes a blob belonging to a namespace.
        :param blob_id: Unique identifier of a blob.
        :type blob_id: str
        :return: A deferred that fires when operation finishes.
        :rtype: Deferred
        """
        return self.blob_manager.delete(blob_id, namespace=self.namespace)
