# -*- coding: utf-8 -*-
# api.py
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
import os
import json
import base64

from StringIO import StringIO
from uuid import uuid4

from twisted.web.error import Error
from twisted.internet import defer
from twisted.web.http_headers import Headers
from twisted.web.client import FileBodyProducer

from leap.soledad.client.http_target.support import readBody
from leap.soledad.common.errors import InvalidAuthTokenError
from leap.soledad.common.l2db import SyncTarget


# we may want to collect statistics from the sync process
DO_STATS = False
if os.environ.get('SOLEDAD_STATS'):
    DO_STATS = True


class SyncTargetAPI(SyncTarget):
    """
    Declares public methods and implements u1db.SyncTarget.
    """

    @property
    def uuid(self):
        return self._uuid

    def set_creds(self, creds):
        """
        Update credentials.

        :param creds: A dictionary containing the uuid and token.
        :type creds: dict
        """
        uuid = creds['token']['uuid']
        token = creds['token']['token']
        self._uuid = uuid
        auth = '%s:%s' % (uuid, token)
        b64_token = base64.b64encode(auth)
        self._auth_header = {'Authorization': ['Token %s' % b64_token]}

    @property
    def _base_header(self):
        return self._auth_header.copy() if self._auth_header else {}

    def _http_request(self, url, method='GET', body=None, headers=None,
                      content_type=None, body_reader=readBody,
                      body_producer=None):
        headers = headers or self._base_header
        if content_type:
            headers.update({'content-type': [content_type]})
        if not body_producer and body:
            body = FileBodyProducer(StringIO(body))
        elif body_producer:
            # Upload case, check send.py
            body = body_producer(body)
        d = self._http.request(
            method, url, headers=Headers(headers), bodyProducer=body)
        d.addCallback(body_reader)
        d.addErrback(_unauth_to_invalid_token_error)
        return d

    @defer.inlineCallbacks
    def get_sync_info(self, source_replica_uid):
        """
        Return information about known state of remote database.

        Return the replica_uid and the current database generation of the
        remote database, and its last-seen database generation for the client
        replica.

        :param source_replica_uid: The client-size replica uid.
        :type source_replica_uid: str

        :return: A deferred which fires with (target_replica_uid,
                 target_replica_generation, target_trans_id,
                 source_replica_last_known_generation,
                 source_replica_last_known_transaction_id)
        :rtype: twisted.internet.defer.Deferred
        """
        raw = yield self._http_request(self._url)
        res = json.loads(raw)
        defer.returnValue((
            res['target_replica_uid'],
            res['target_replica_generation'],
            res['target_replica_transaction_id'],
            res['source_replica_generation'],
            res['source_transaction_id']
        ))

    def record_sync_info(
            self, source_replica_uid, source_replica_generation,
            source_replica_transaction_id):
        """
        Record tip information for another replica.

        After sync_exchange has been processed, the caller will have
        received new content from this replica. This call allows the
        source replica instigating the sync to inform us what their
        generation became after applying the documents we returned.

        This is used to allow future sync operations to not need to repeat data
        that we just talked about. It also means that if this is called at the
        wrong time, there can be database records that will never be
        synchronized.

        :param source_replica_uid: The identifier for the source replica.
        :type source_replica_uid: str
        :param source_replica_generation: The database generation for the
                                          source replica.
        :type source_replica_generation: int
        :param source_replica_transaction_id: The transaction id associated
                                              with the source replica
                                              generation.
        :type source_replica_transaction_id: str

        :return: A deferred which fires with the result of the query.
        :rtype: twisted.internet.defer.Deferred
        """
        data = json.dumps({
            'generation': source_replica_generation,
            'transaction_id': source_replica_transaction_id
        })
        return self._http_request(
            self._url,
            method='PUT',
            body=data,
            content_type='application/json')

    @defer.inlineCallbacks
    def sync_exchange(self, docs_by_generation, source_replica_uid,
                      last_known_generation, last_known_trans_id,
                      insert_doc_cb, ensure_callback=None,
                      sync_id=None):
        """
        Find out which documents the remote database does not know about,
        encrypt and send them. After that, receive documents from the remote
        database.

        :param docs_by_generations: A list of (doc_id, generation, trans_id)
                                    of local documents that were changed since
                                    the last local generation the remote
                                    replica knows about.
        :type docs_by_generations: list of tuples

        :param source_replica_uid: The uid of the source replica.
        :type source_replica_uid: str

        :param last_known_generation: Target's last known generation.
        :type last_known_generation: int

        :param last_known_trans_id: Target's last known transaction id.
        :type last_known_trans_id: str

        :param insert_doc_cb: A callback for inserting received documents from
                              target. If not overriden, this will call u1db
                              insert_doc_from_target in synchronizer, which
                              implements the TAKE OTHER semantics.
        :type insert_doc_cb: function

        :param ensure_callback: A callback that ensures we know the target
                                replica uid if the target replica was just
                                created.
        :type ensure_callback: function

        :return: A deferred which fires with the new generation and
                 transaction id of the target replica.
        :rtype: twisted.internet.defer.Deferred
        """
        # ---------- phase 1: send docs to server ----------------------------
        if DO_STATS:
            self.sync_exchange_phase[0] += 1
        # --------------------------------------------------------------------

        self._ensure_callback = ensure_callback

        if sync_id is None:
            sync_id = str(uuid4())
        self.source_replica_uid = source_replica_uid

        # save a reference to the callback so we can use it after decrypting
        self._insert_doc_cb = insert_doc_cb

        gen_after_send, trans_id_after_send = yield self._send_docs(
            docs_by_generation,
            last_known_generation,
            last_known_trans_id,
            sync_id)

        # ---------- phase 2: receive docs -----------------------------------
        if DO_STATS:
            self.sync_exchange_phase[0] += 1
        # --------------------------------------------------------------------

        cur_target_gen, cur_target_trans_id = yield self._receive_docs(
            last_known_generation, last_known_trans_id,
            ensure_callback, sync_id)

        # update gen and trans id info in case we just sent and did not
        # receive docs.
        if gen_after_send is not None and gen_after_send > cur_target_gen:
            cur_target_gen = gen_after_send
            cur_target_trans_id = trans_id_after_send

        # ---------- phase 3: sync exchange is over --------------------------
        if DO_STATS:
            self.sync_exchange_phase[0] += 1
        # --------------------------------------------------------------------

        defer.returnValue([cur_target_gen, cur_target_trans_id])


def _unauth_to_invalid_token_error(failure):
    """
    An errback to translate unauthorized errors to our own invalid token
    class.

    :param failure: The original failure.
    :type failure: twisted.python.failure.Failure

    :return: Either the original failure or an invalid auth token error.
    :rtype: twisted.python.failure.Failure
    """
    failure.trap(Error)
    if failure.getErrorMessage() == "401 Unauthorized":
        raise InvalidAuthTokenError
    return failure
