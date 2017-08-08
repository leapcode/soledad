# -*- coding: utf-8 -*-
# test_incoming_processing_flow.py
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
Unit tests for incoming box processing flow.
"""
from mock import Mock, call
from leap.soledad.client import interfaces
from leap.soledad.client.incoming import IncomingBoxProcessingLoop
from twisted.internet import defer
from twisted.trial import unittest
from zope.interface import implementer


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


class ProcessingFailedConsumer(GoodConsumer):
    def __init__(self):
        self.name = 'ProcessingFailedConsumer'
        self.processed, self.saved = [], []

    def process(self, item, item_id, encrypted=True):
        return defer.fail()


class SavingFailedConsumer(GoodConsumer):
    def __init__(self):
        self.name = 'SavingFailedConsumer'
        self.processed, self.saved = [], []

    def save(self, parts, item_id):
        return defer.fail()


class IncomingBoxProcessingTestCase(unittest.TestCase):

    def setUp(self):
        self.box = Mock()
        self.loop = IncomingBoxProcessingLoop(self.box)

    def _set_pending_items(self, pending):
        self.box.list_pending.return_value = defer.succeed(pending)
        pending_iter = iter([defer.succeed(item) for item in pending])
        self.box.fetch_for_processing.side_effect = pending_iter

    @defer.inlineCallbacks
    def test_processing_flow_reserves_a_message(self):
        self._set_pending_items(['one_item'])
        self.loop.add_consumer(GoodConsumer())
        yield self.loop()
        self.box.fetch_for_processing.assert_called_once_with('one_item')

    @defer.inlineCallbacks
    def test_no_consumers(self):
        items = ['one', 'two', 'three']
        self._set_pending_items(items)
        yield self.loop()
        self.box.fetch_for_processing.assert_not_called()
        self.box.delete.assert_not_called()

    @defer.inlineCallbacks
    def test_pending_list_with_multiple_items(self):
        items = ['one', 'two', 'three']
        self._set_pending_items(items)
        consumer = GoodConsumer()
        self.loop.add_consumer(consumer)
        yield self.loop()
        calls = [call('one'), call('two'), call('three')]
        self.box.fetch_for_processing.assert_has_calls(calls)

    @defer.inlineCallbacks
    def test_good_consumer_process_all(self):
        items = ['one', 'two', 'three']
        self._set_pending_items(items)
        consumer = GoodConsumer()
        self.loop.add_consumer(consumer)
        yield self.loop()
        self.assertEquals(items, consumer.processed)

    @defer.inlineCallbacks
    def test_good_consumer_saves_all(self):
        items = ['one', 'two', 'three']
        self._set_pending_items(items)
        consumer = GoodConsumer()
        self.loop.add_consumer(consumer)
        yield self.loop()
        self.assertEquals(items, consumer.saved)

    @defer.inlineCallbacks
    def test_multiple_good_consumers_process_all(self):
        items = ['one', 'two', 'three']
        self._set_pending_items(items)
        consumer = GoodConsumer()
        consumer2 = GoodConsumer()
        self.loop.add_consumer(consumer)
        self.loop.add_consumer(consumer2)
        yield self.loop()
        self.assertEquals(items, consumer.processed)
        self.assertEquals(items, consumer2.processed)

    @defer.inlineCallbacks
    def test_good_consumer_marks_as_processed(self):
        items = ['one', 'two', 'three']
        self._set_pending_items(items)
        consumer = GoodConsumer()
        self.loop.add_consumer(consumer)
        yield self.loop()
        self.box.set_processed.has_calls([call(x) for x in items])

    @defer.inlineCallbacks
    def test_good_consumer_deletes_items(self):
        items = ['one', 'two', 'three']
        self._set_pending_items(items)
        consumer = GoodConsumer()
        self.loop.add_consumer(consumer)
        yield self.loop()
        self.box.delete.has_calls([call(x) for x in items])

    @defer.inlineCallbacks
    def test_processing_failed_doesnt_mark_as_processed(self):
        items = ['one', 'two', 'three']
        self._set_pending_items(items)
        consumer = ProcessingFailedConsumer()
        self.loop.add_consumer(consumer)
        yield self.loop()
        self.box.set_processed.assert_not_called()

    @defer.inlineCallbacks
    def test_processing_failed_doesnt_delete(self):
        items = ['one', 'two', 'three']
        self._set_pending_items(items)
        consumer = ProcessingFailedConsumer()
        self.loop.add_consumer(consumer)
        yield self.loop()
        self.box.delete.assert_not_called()

    @defer.inlineCallbacks
    def test_processing_failed_marks_as_failed(self):
        items = ['one', 'two', 'three']
        self._set_pending_items(items)
        consumer = ProcessingFailedConsumer()
        self.loop.add_consumer(consumer)
        yield self.loop()
        self.box.set_failed.assert_has_calls([call(x) for x in items])

    @defer.inlineCallbacks
    def test_saving_failed_marks_as_processed(self):
        items = ['one', 'two', 'three']
        self._set_pending_items(items)
        consumer = SavingFailedConsumer()
        self.loop.add_consumer(consumer)
        yield self.loop()
        self.box.set_processed.assert_has_calls([call(x) for x in items])

    @defer.inlineCallbacks
    def test_saving_failed_doesnt_delete(self):
        items = ['one', 'two', 'three']
        self._set_pending_items(items)
        consumer = SavingFailedConsumer()
        self.loop.add_consumer(consumer)
        yield self.loop()
        self.box.delete.assert_not_called()

    @defer.inlineCallbacks
    def test_saving_failed_marks_as_failed(self):
        items = ['one', 'two', 'three']
        self._set_pending_items(items)
        consumer = SavingFailedConsumer()
        self.loop.add_consumer(consumer)
        yield self.loop()
        self.box.set_failed.assert_has_calls([call(x) for x in items])
