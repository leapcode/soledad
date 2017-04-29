# -*- coding: utf-8 -*-
# test_attachments.py
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
Tests for document attachments.
"""

import pytest

from io import BytesIO
from mock import Mock

from twisted.internet import defer
from test_soledad.util import BaseSoledadTest


from leap.soledad.client import AttachmentStates


def mock_response(doc):
    doc._manager._client.get = Mock(
        return_value=defer.succeed(Mock(code=200, json=lambda: [])))
    doc._manager._client.put = Mock(
        return_value=defer.succeed(Mock(code=200)))


@pytest.mark.usefixture('method_tmpdir')
class AttachmentTests(BaseSoledadTest):

    @defer.inlineCallbacks
    def test_create_doc_saves_store(self):
        doc = yield self._soledad.create_doc({})
        self.assertEqual(self._soledad, doc.store)

    @defer.inlineCallbacks
    def test_put_attachment(self):
        doc = yield self._soledad.create_doc({})
        mock_response(doc)
        yield doc.put_attachment(BytesIO('test'))
        local_list = yield doc._manager.local_list()
        self.assertIn(doc._blob_id, local_list)

    @defer.inlineCallbacks
    def test_get_attachment(self):
        doc = yield self._soledad.create_doc({})
        mock_response(doc)
        yield doc.put_attachment(BytesIO('test'))
        fd = yield doc.get_attachment()
        self.assertEqual('test', fd.read())

    @defer.inlineCallbacks
    def test_attachment_state(self):
        doc = yield self._soledad.create_doc({})
        state = yield doc.attachment_state()
        self.assertEqual(AttachmentStates.NONE, state)
        mock_response(doc)
        yield doc.put_attachment(BytesIO('test'))
        state = yield doc.attachment_state()
        self.assertEqual(AttachmentStates.LOCAL, state)

    @defer.inlineCallbacks
    def test_is_dirty(self):
        doc = yield self._soledad.create_doc({})
        dirty = yield doc.is_dirty()
        self.assertFalse(dirty)
        doc.content = {'test': True}
        dirty = yield doc.is_dirty()
        self.assertTrue(dirty)
