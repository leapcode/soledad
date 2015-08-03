# -*- coding: utf-8 -*-
# http_target.py
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


"""
A U1DB backend for encrypting data before sending to server and decrypting
after receiving.
"""


import json
import base64
import logging

from uuid import uuid4

from twisted.internet import defer
from twisted.web.error import Error

from u1db import errors
from u1db import SyncTarget
from u1db.remote import utils

from leap.common.http import HTTPClient

from leap.soledad.common.document import SoledadDocument
from leap.soledad.common.errors import InvalidAuthTokenError

from leap.soledad.client.crypto import is_symmetrically_encrypted
from leap.soledad.client.crypto import encrypt_doc
from leap.soledad.client.crypto import decrypt_doc
from leap.soledad.client.events import SOLEDAD_SYNC_SEND_STATUS
from leap.soledad.client.events import SOLEDAD_SYNC_RECEIVE_STATUS
from leap.soledad.client.events import emit
from leap.soledad.client.encdecpool import SyncDecrypterPool


logger = logging.getLogger(__name__)


class SoledadHTTPSyncTarget(SyncTarget):

    """
    A SyncTarget that encrypts data before sending and decrypts data after
    receiving.

    Normally encryption will have been written to the sync database upon
    document modification. The sync database is also used to write temporarily
    the parsed documents that the remote send us, before being decrypted and
    written to the main database.
    """

    def __init__(self, url, source_replica_uid, creds, crypto, cert_file,
                 sync_db=None, sync_enc_pool=None):
        """
        Initialize the sync target.

        :param url: The server sync url.
        :type url: str
        :param source_replica_uid: The source replica uid which we use when
                                   deferring decryption.
        :type source_replica_uid: str
        :param creds: A dictionary containing the uuid and token.
        :type creds: creds
        :param crypto: An instance of SoledadCrypto so we can encrypt/decrypt
                        document contents when syncing.
        :type crypto: soledad.crypto.SoledadCrypto
        :param cert_file: Path to the certificate of the ca used to validate
                          the SSL certificate used by the remote soledad
                          server.
        :type cert_file: str
        :param sync_db: Optional. handler for the db with the symmetric
                        encryption of the syncing documents. If
                        None, encryption will be done in-place,
                        instead of retreiving it from the dedicated
                        database.
        :type sync_db: Sqlite handler
        :param verify_ssl: Whether we should perform SSL server certificate
                           verification.
        :type verify_ssl: bool
        """
        if url.endswith("/"):
            url = url[:-1]
        self._url = str(url) + "/sync-from/" + str(source_replica_uid)
        self.source_replica_uid = source_replica_uid
        self._auth_header = None
        self.set_creds(creds)
        self._crypto = crypto
        self._sync_db = sync_db
        self._sync_enc_pool = sync_enc_pool
        self._insert_doc_cb = None
        # asynchronous encryption/decryption attributes
        self._decryption_callback = None
        self._sync_decr_pool = None
        self._http = HTTPClient(cert_file)

    def close(self):
        self._http.close()

    def set_creds(self, creds):
        """
        Update credentials.

        :param creds: A dictionary containing the uuid and token.
        :type creds: dict
        """
        uuid = creds['token']['uuid']
        token = creds['token']['token']
        auth = '%s:%s' % (uuid, token)
        b64_token = base64.b64encode(auth)
        self._auth_header = {'Authorization': ['Token %s' % b64_token]}

    @property
    def _defer_encryption(self):
        return self._sync_enc_pool is not None

    #
    # SyncTarget API
    #

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
        raw = yield self._http_request(self._url, headers=self._auth_header)
        res = json.loads(raw)
        defer.returnValue([
            res['target_replica_uid'],
            res['target_replica_generation'],
            res['target_replica_transaction_id'],
            res['source_replica_generation'],
            res['source_transaction_id']
        ])

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
        headers = self._auth_header.copy()
        headers.update({'content-type': ['application/json']})
        return self._http_request(
            self._url,
            method='PUT',
            headers=headers,
            body=data)

    @defer.inlineCallbacks
    def sync_exchange(self, docs_by_generation, source_replica_uid,
                      last_known_generation, last_known_trans_id,
                      insert_doc_cb, ensure_callback=None,
                      defer_decryption=True, sync_id=None):
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

        :param defer_decryption: Whether to defer the decryption process using
                                 the intermediate database. If False,
                                 decryption will be done inline.
        :type defer_decryption: bool

        :return: A deferred which fires with the new generation and
                 transaction id of the target replica.
        :rtype: twisted.internet.defer.Deferred
        """

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

        cur_target_gen, cur_target_trans_id = yield self._receive_docs(
            last_known_generation, last_known_trans_id,
            ensure_callback, sync_id,
            defer_decryption=defer_decryption)

        # update gen and trans id info in case we just sent and did not
        # receive docs.
        if gen_after_send is not None and gen_after_send > cur_target_gen:
            cur_target_gen = gen_after_send
            cur_target_trans_id = trans_id_after_send

        defer.returnValue([cur_target_gen, cur_target_trans_id])

    #
    # methods to send docs
    #

    def _prepare(self, comma, entries, **dic):
        entry = comma + '\r\n' + json.dumps(dic)
        entries.append(entry)
        return len(entry)

    @defer.inlineCallbacks
    def _send_docs(self, docs_by_generation, last_known_generation,
                   last_known_trans_id, sync_id):

        if not docs_by_generation:
            defer.returnValue([None, None])

        headers = self._auth_header.copy()
        headers.update({'content-type': ['application/x-soledad-sync-put']})
        # add remote replica metadata to the request
        first_entries = ['[']
        self._prepare(
            '', first_entries,
            last_known_generation=last_known_generation,
            last_known_trans_id=last_known_trans_id,
            sync_id=sync_id,
            ensure=self._ensure_callback is not None)
        idx = 0
        total = len(docs_by_generation)
        for doc, gen, trans_id in docs_by_generation:
            idx += 1
            result = yield self._send_one_doc(
                headers, first_entries, doc,
                gen, trans_id, total, idx)
            if self._defer_encryption:
                self._sync_enc_pool.delete_encrypted_doc(
                    doc.doc_id, doc.rev)
            msg = "%d/%d" % (idx, total)
            emit(
                SOLEDAD_SYNC_SEND_STATUS,
                "Soledad sync send status: %s" % msg)
            logger.debug("Sync send status: %s" % msg)
        response_dict = json.loads(result)[0]
        gen_after_send = response_dict['new_generation']
        trans_id_after_send = response_dict['new_transaction_id']
        defer.returnValue([gen_after_send, trans_id_after_send])

    @defer.inlineCallbacks
    def _send_one_doc(self, headers, first_entries, doc, gen, trans_id,
                      number_of_docs, doc_idx):
        entries = first_entries[:]
        # add the document to the request
        content = yield self._encrypt_doc(doc)
        self._prepare(
            ',', entries,
            id=doc.doc_id, rev=doc.rev, content=content, gen=gen,
            trans_id=trans_id, number_of_docs=number_of_docs,
            doc_idx=doc_idx)
        entries.append('\r\n]')
        data = ''.join(entries)
        result = yield self._http_request(
            self._url,
            method='POST',
            headers=headers,
            body=data)
        defer.returnValue(result)

    def _encrypt_doc(self, doc):
        d = None
        if doc.is_tombstone():
            d = defer.succeed(None)
        elif not self._defer_encryption:
            # fallback case, for tests
            d = defer.succeed(encrypt_doc(self._crypto, doc))
        else:

            def _maybe_encrypt_doc_inline(doc_json):
                if doc_json is None:
                    # the document is not marked as tombstone, but we got
                    # nothing from the sync db. As it is not encrypted
                    # yet, we force inline encryption.
                    return encrypt_doc(self._crypto, doc)
                return doc_json

            d = self._sync_enc_pool.get_encrypted_doc(doc.doc_id, doc.rev)
            d.addCallback(_maybe_encrypt_doc_inline)
        return d

    #
    # methods to receive doc
    #

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

        headers = self._auth_header.copy()
        headers.update({'content-type': ['application/x-soledad-sync-get']})

        # ---------------------------------------------------------------------
        # maybe receive the first document
        # ---------------------------------------------------------------------

        # we fetch the first document before fetching the rest because we need
        # to know the total number of documents to be received, and this
        # information comes as metadata to each request.

        doc = yield self._receive_one_doc(
            headers, last_known_generation, last_known_trans_id,
            sync_id, 0)
        self._received_docs = 0
        number_of_changes, ngen, ntrans = self._insert_received_doc(doc, 1, 1)

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
                headers, last_known_generation,
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

    def _receive_one_doc(self, headers, last_known_generation,
                         last_known_trans_id, sync_id, received):
        entries = ['[']
        # add remote replica metadata to the request
        self._prepare(
            '', entries,
            last_known_generation=last_known_generation,
            last_known_trans_id=last_known_trans_id,
            sync_id=sync_id,
            ensure=self._ensure_callback is not None)
        # inform server of how many documents have already been received
        self._prepare(
            ',', entries, received=received)
        entries.append('\r\n]')
        # send headers
        return self._http_request(
            self._url,
            method='POST',
            headers=headers,
            body=''.join(entries))

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
                    doc.set_json(decrypt_doc(self._crypto, doc))
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
        msg = "%d/%d" % (self._received_docs, total)
        emit(SOLEDAD_SYNC_RECEIVE_STATUS, msg)
        logger.debug("Sync receive status: %s" % msg)
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
        line, comma = utils.check_and_strip_comma(data[0])
        metadata = None
        try:
            metadata = json.loads(line)
            new_generation = metadata['new_generation']
            new_transaction_id = metadata['new_transaction_id']
            number_of_changes = metadata['number_of_changes']
        except (json.JSONDecodeError, KeyError):
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

    def _http_request(self, url, method='GET', body=None, headers={}):
        d = self._http.request(url, method, body, headers)
        d.addErrback(_unauth_to_invalid_token_error)
        return d


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
