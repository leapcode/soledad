# -*- coding: utf-8 -*-
# send.py
# Copyright (C) 2015 LEAP
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
import json

from twisted.internet import defer

from leap.soledad.common.log import getLogger
from leap.soledad.client.events import emit_async
from leap.soledad.client.events import SOLEDAD_SYNC_SEND_STATUS
from leap.soledad.client.http_target.support import RequestBody
from .send_protocol import DocStreamProducer

logger = getLogger(__name__)


class HTTPDocSender(object):
    """
    Handles Document uploading from Soledad server, using HTTP as transport.
    They need to be encrypted and metadata prepared before sending.
    """

    # The uuid of the local replica.
    # Any class inheriting from this one should provide a meaningful attribute
    # if the sync status event is meant to be used somewhere else.

    uuid = 'undefined'
    userid = 'undefined'

    @defer.inlineCallbacks
    def _send_docs(self, docs_by_generation, last_known_generation,
                   last_known_trans_id, sync_id):

        if not docs_by_generation:
            defer.returnValue([None, None])

        # add remote replica metadata to the request
        body = RequestBody(
            last_known_generation=last_known_generation,
            last_known_trans_id=last_known_trans_id,
            sync_id=sync_id,
            ensure=self._ensure_callback is not None)
        result = yield self._send_batch(body, docs_by_generation)
        response_dict = json.loads(result)[0]
        gen_after_send = response_dict['new_generation']
        trans_id_after_send = response_dict['new_transaction_id']
        defer.returnValue([gen_after_send, trans_id_after_send])

    @defer.inlineCallbacks
    def _send_batch(self, body, docs):
        total, calls = len(docs), []
        for i, entry in enumerate(docs):
            calls.append((self._prepare_one_doc,
                         entry, body, i + 1, total))
        result = yield self._send_request(body, calls)
        _emit_send_status(self.uuid, body.consumed, total)

        defer.returnValue(result)

    def _send_request(self, body, calls):
        return self._http_request(
            self._url,
            method='POST',
            body=(body, calls),
            content_type='application/x-soledad-sync-put',
            body_producer=DocStreamProducer)

    @defer.inlineCallbacks
    def _prepare_one_doc(self, entry, body, idx, total):
        get_doc_call, gen, trans_id = entry
        doc, content = yield self._encrypt_doc(get_doc_call)
        body.insert_info(
            id=doc.doc_id, rev=doc.rev, content=content, gen=gen,
            trans_id=trans_id, number_of_docs=total,
            doc_idx=idx)
        _emit_send_status(self.uuid, body.consumed, total)

    @defer.inlineCallbacks
    def _encrypt_doc(self, get_doc_call):
        f, args, kwargs = get_doc_call
        doc = yield f(*args, **kwargs)
        if doc.is_tombstone():
            defer.returnValue((doc, None))
        else:
            content = yield self._crypto.encrypt_doc(doc)
            defer.returnValue((doc, content))


def _emit_send_status(user_data, idx, total):
    content = {'sent': idx, 'total': total}
    emit_async(SOLEDAD_SYNC_SEND_STATUS, user_data, content)

    msg = "%d/%d" % (idx, total)
    logger.debug("Sync send status: %s" % msg)
