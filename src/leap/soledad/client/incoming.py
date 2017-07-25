# -*- coding: utf-8 -*-
# incoming.py
# Copyright (C) 2014 LEAP
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
from twisted.logger import Logger
from twisted.internet.task import LoopingCall
from twisted.internet import defer
log = Logger()


class IncomingBoxProcessingLoop(object):
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
