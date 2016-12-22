# -*- coding: utf-8 -*-
# fetch.py
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
from twisted.internet import threads

from leap.soledad.client.events import SOLEDAD_SYNC_RECEIVE_STATUS
from leap.soledad.client.events import emit_async
from leap.soledad.client.http_target.support import RequestBody
from leap.soledad.common.log import getLogger
from leap.soledad.client._crypto import is_symmetrically_encrypted
from leap.soledad.common.document import SoledadDocument
from leap.soledad.common.l2db import errors
from leap.soledad.client import crypto as old_crypto

from . import fetch_protocol

logger = getLogger(__name__)


class HTTPDocFetcher(object):
    """
    Handles Document fetching from Soledad server, using HTTP as transport.
    Steps:
    * Prepares metadata by asking server for one document
    * Fetch the total on response and prepare to ask all remaining
    * (async) Documents will come encrypted.
              So we parse, decrypt and insert locally as they arrive.
    """

    # The uuid of the local replica.
    # Any class inheriting from this one should provide a meaningful attribute
    # if the sync status event is meant to be used somewhere else.

    uuid = 'undefined'
    userid = 'undefined'

    @defer.inlineCallbacks
    def _receive_docs(self, last_known_generation, last_known_trans_id,
                      ensure_callback, sync_id):
        new_generation = last_known_generation
        new_transaction_id = last_known_trans_id
        # Acts as a queue, ensuring line order on async processing
        # as `self._insert_doc_cb` cant be run concurrently or out of order.
        # DeferredSemaphore solves the concurrency and its implementation uses
        # a queue, solving the ordering.
        # FIXME: Find a proper solution to avoid surprises on Twisted changes
        self.semaphore = defer.DeferredSemaphore(1)

        metadata = yield self._fetch_all(
            last_known_generation, last_known_trans_id,
            sync_id)
        number_of_changes, ngen, ntrans = self._parse_metadata(metadata)

        # wait for pending inserts
        yield self.semaphore.acquire()

        if ngen:
            new_generation = ngen
            new_transaction_id = ntrans

        defer.returnValue([new_generation, new_transaction_id])

    def _fetch_all(self, last_known_generation,
                   last_known_trans_id, sync_id):
        # add remote replica metadata to the request
        body = RequestBody(
            last_known_generation=last_known_generation,
            last_known_trans_id=last_known_trans_id,
            sync_id=sync_id,
            ensure=self._ensure_callback is not None)
        self._received_docs = 0
        # build a stream reader with _doc_parser as a callback
        body_reader = fetch_protocol.build_body_reader(self._doc_parser)
        # start download stream
        return self._http_request(
            self._url,
            method='POST',
            body=str(body),
            content_type='application/x-soledad-sync-get',
            body_reader=body_reader)

    @defer.inlineCallbacks
    def _doc_parser(self, doc_info, content, total):
        """
        Insert a received document into the local replica, decrypting
        if necessary. The case where it's not decrypted is when a doc gets
        inserted from Server side with a GPG encrypted content.

        :param doc_info: Dictionary representing Document information.
        :type doc_info: dict
        :param content: The Document's content.
        :type idx: str
        :param total: The total number of operations.
        :type total: int
        """
        yield self.semaphore.run(self.__atomic_doc_parse, doc_info, content,
                                 total)

    @defer.inlineCallbacks
    def __atomic_doc_parse(self, doc_info, content, total):
        doc = SoledadDocument(doc_info['id'], doc_info['rev'], content)
        if is_symmetrically_encrypted(content):
            content = yield self._crypto.decrypt_doc(doc)
        elif old_crypto.is_symmetrically_encrypted(doc):
            content = self._deprecated_crypto.decrypt_doc(doc)
        doc.set_json(content)

        # TODO insert blobs here on the blob backend
        # FIXME: This is wrong. Using the very same SQLite connection object
        # from multiple threads is dangerous. We should bring the dbpool here
        # or find an alternative.  Deferring to a thread only helps releasing
        # the reactor for other tasks as this is an IO intensive call.
        yield threads.deferToThread(self._insert_doc_cb,
                                    doc, doc_info['gen'], doc_info['trans_id'])
        self._received_docs += 1
        user_data = {'uuid': self.uuid, 'userid': self.userid}
        _emit_receive_status(user_data, self._received_docs, total=total)

    def _parse_metadata(self, metadata):
        """
        Parse the response from the server containing the sync metadata.

        :param response: Metadata as string
        :type response: str

        :return: (number_of_changes, new_gen, new_trans_id)
        :rtype: tuple
        """
        try:
            metadata = json.loads(metadata)
            # make sure we have replica_uid from fresh new dbs
            if self._ensure_callback and 'replica_uid' in metadata:
                self._ensure_callback(metadata['replica_uid'])
            return (metadata['number_of_changes'], metadata['new_generation'],
                    metadata['new_transaction_id'])
        except (ValueError, KeyError):
            raise errors.BrokenSyncStream('Metadata parsing failed')


def _emit_receive_status(user_data, received_docs, total):
    content = {'received': received_docs, 'total': total}
    emit_async(SOLEDAD_SYNC_RECEIVE_STATUS, user_data, content)

    if received_docs % 20 == 0:
        msg = "%d/%d" % (received_docs, total)
        logger.debug("Sync receive status: %s" % msg)
