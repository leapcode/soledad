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
import logging
import json
from u1db import errors
from u1db.remote import utils
from twisted.internet import defer
from leap.soledad.common.document import SoledadDocument
from leap.soledad.client.events import SOLEDAD_SYNC_RECEIVE_STATUS
from leap.soledad.client.events import emit_async
from leap.soledad.client.crypto import is_symmetrically_encrypted
from leap.soledad.client.encdecpool import SyncDecrypterPool
from leap.soledad.client.http_target.support import RequestBody

logger = logging.getLogger(__name__)


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
                      ensure_callback, sync_id, defer_decryption):

        self._queue_for_decrypt = defer_decryption \
            and self._sync_db is not None

        new_generation = last_known_generation
        new_transaction_id = last_known_trans_id

        if self._queue_for_decrypt:
            logger.debug(
                "Soledad sync: will queue received docs for decrypting.")

        if defer_decryption:
            self._setup_sync_decr_pool()

        # ---------------------------------------------------------------------
        # maybe receive the first document
        # ---------------------------------------------------------------------

        # we fetch the first document before fetching the rest because we need
        # to know the total number of documents to be received, and this
        # information comes as metadata to each request.

        doc = yield self._receive_one_doc(
            last_known_generation, last_known_trans_id,
            sync_id, 0)
        self._received_docs = 0
        number_of_changes, ngen, ntrans = self._insert_received_doc(doc, 1, 1)

        if ngen:
            new_generation = ngen
            new_transaction_id = ntrans

        if defer_decryption:
            self._sync_decr_pool.start(number_of_changes)

        # ---------------------------------------------------------------------
        # maybe receive the rest of the documents
        # ---------------------------------------------------------------------

        # launch many asynchronous fetches and inserts of received documents
        # in the temporary sync db. Will wait for all results before
        # continuing.

        received = 1
        deferreds = []
        while received < number_of_changes:
            d = self._receive_one_doc(
                last_known_generation,
                last_known_trans_id, sync_id, received)
            d.addCallback(
                self._insert_received_doc,
                received + 1,  # the index of the current received doc
                number_of_changes)
            deferreds.append(d)
            received += 1
        results = yield defer.gatherResults(deferreds)

        # get generation and transaction id of target after insertions
        if deferreds:
            _, new_generation, new_transaction_id = results.pop()

        # ---------------------------------------------------------------------
        # wait for async decryption to finish
        # ---------------------------------------------------------------------

        if defer_decryption:
            yield self._sync_decr_pool.deferred
            self._sync_decr_pool.stop()

        defer.returnValue([new_generation, new_transaction_id])

    def _receive_one_doc(self, last_known_generation,
                         last_known_trans_id, sync_id, received):
        # add remote replica metadata to the request
        body = RequestBody(
            last_known_generation=last_known_generation,
            last_known_trans_id=last_known_trans_id,
            sync_id=sync_id,
            ensure=self._ensure_callback is not None)
        # inform server of how many documents have already been received
        body.insert_info(received=received)
        # send headers
        return self._http_request(
            self._url,
            method='POST',
            body=str(body),
            content_type='application/x-soledad-sync-get')

    def _insert_received_doc(self, response, idx, total):
        """
        Insert a received document into the local replica.

        :param response: The body and headers of the response.
        :type response: tuple(str, dict)
        :param idx: The index count of the current operation.
        :type idx: int
        :param total: The total number of operations.
        :type total: int
        """
        new_generation, new_transaction_id, number_of_changes, doc_id, \
            rev, content, gen, trans_id = \
            self._parse_received_doc_response(response)
        if doc_id is not None:
            # decrypt incoming document and insert into local database
            # -------------------------------------------------------------
            # symmetric decryption of document's contents
            # -------------------------------------------------------------
            # If arriving content was symmetrically encrypted, we decrypt it.
            # We do it inline if defer_decryption flag is False or no sync_db
            # was defined, otherwise we defer it writing it to the received
            # docs table.
            doc = SoledadDocument(doc_id, rev, content)
            if is_symmetrically_encrypted(doc):
                if self._queue_for_decrypt:
                    self._sync_decr_pool.insert_encrypted_received_doc(
                        doc.doc_id, doc.rev, doc.content, gen, trans_id,
                        idx)
                else:
                    # defer_decryption is False or no-sync-db fallback
                    doc.set_json(self._crypto.decrypt_doc(doc))
                    self._insert_doc_cb(doc, gen, trans_id)
            else:
                # not symmetrically encrypted doc, insert it directly
                # or save it in the decrypted stage.
                if self._queue_for_decrypt:
                    self._sync_decr_pool.insert_received_doc(
                        doc.doc_id, doc.rev, doc.content, gen, trans_id,
                        idx)
                else:
                    self._insert_doc_cb(doc, gen, trans_id)
            # -------------------------------------------------------------
            # end of symmetric decryption
            # -------------------------------------------------------------
        self._received_docs += 1
        user_data = {'uuid': self.uuid, 'userid': self.userid}
        _emit_receive_status(user_data, self._received_docs, total)
        return number_of_changes, new_generation, new_transaction_id

    def _parse_received_doc_response(self, response):
        """
        Parse the response from the server containing the received document.

        :param response: The body and headers of the response.
        :type response: tuple(str, dict)

        :return: (new_gen, new_trans_id, number_of_changes, doc_id, rev,
                 content, gen, trans_id)
        :rtype: tuple
        """
        # decode incoming stream
        parts = response.splitlines()
        if not parts or parts[0] != '[' or parts[-1] != ']':
            raise errors.BrokenSyncStream
        data = parts[1:-1]
        # decode metadata
        try:
            line, comma = utils.check_and_strip_comma(data[0])
            metadata = None
        except (IndexError):
            raise errors.BrokenSyncStream
        try:
            metadata = json.loads(line)
            new_generation = metadata['new_generation']
            new_transaction_id = metadata['new_transaction_id']
            number_of_changes = metadata['number_of_changes']
        except (ValueError, KeyError):
            raise errors.BrokenSyncStream
        # make sure we have replica_uid from fresh new dbs
        if self._ensure_callback and 'replica_uid' in metadata:
            self._ensure_callback(metadata['replica_uid'])
        # parse incoming document info
        doc_id = None
        rev = None
        content = None
        gen = None
        trans_id = None
        if number_of_changes > 0:
            try:
                entry = json.loads(data[1])
                doc_id = entry['id']
                rev = entry['rev']
                content = entry['content']
                gen = entry['gen']
                trans_id = entry['trans_id']
            except (IndexError, KeyError):
                raise errors.BrokenSyncStream
        return new_generation, new_transaction_id, number_of_changes, \
            doc_id, rev, content, gen, trans_id

    def _setup_sync_decr_pool(self):
        """
        Set up the SyncDecrypterPool for deferred decryption.
        """
        if self._sync_decr_pool is None and self._sync_db is not None:
            # initialize syncing queue decryption pool
            self._sync_decr_pool = SyncDecrypterPool(
                self._crypto,
                self._sync_db,
                insert_doc_cb=self._insert_doc_cb,
                source_replica_uid=self.source_replica_uid)


def _emit_receive_status(user_data, received_docs, total):
    content = {'received': received_docs, 'total': total}
    emit_async(SOLEDAD_SYNC_RECEIVE_STATUS, user_data, content)

    if received_docs % 20 == 0:
        msg = "%d/%d" % (received_docs, total)
        logger.debug("Sync receive status: %s" % msg)
