# -*- coding: utf-8 -*-
# sync.py
# Copyright (C) 2014 LEAP
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
Server side synchronization infrastructure.
"""
from u1db import sync, Document
from u1db.remote import http_app
from leap.soledad.server.state import ServerSyncState
from leap.soledad.server.caching import get_cache_for


MAX_REQUEST_SIZE = 200  # in Mb
MAX_ENTRY_SIZE = 200  # in Mb


class SyncExchange(sync.SyncExchange):

    def __init__(self, db, source_replica_uid, last_known_generation, sync_id):
        """
        :param db: The target syncing database.
        :type db: SoledadBackend
        :param source_replica_uid: The uid of the source syncing replica.
        :type source_replica_uid: str
        :param last_known_generation: The last target replica generation the
                                      source replica knows about.
        :type last_known_generation: int
        :param sync_id: The id of the current sync session.
        :type sync_id: str
        """
        self._db = db
        self.source_replica_uid = source_replica_uid
        self.source_last_known_generation = last_known_generation
        self.sync_id = sync_id
        self.new_gen = None
        self.new_trans_id = None
        self._trace_hook = None
        # recover sync state
        self._sync_state = ServerSyncState(self.source_replica_uid, sync_id)

    def find_changes_to_return(self, received):
        """
        Find changes to return.

        Find changes since last_known_generation in db generation
        order using whats_changed. It excludes documents ids that have
        already been considered (superseded by the sender, etc).

        :param received: How many documents the source replica has already
                         received during the current sync process.
        :type received: int

        :return: the generation of this database, which the caller can
                 consider themselves to be synchronized after processing
                 allreturned documents, and the amount of documents to be sent
                 to the source syncing replica.
        :rtype: int
        """
        # check if changes to return have already been calculated
        new_gen, new_trans_id, number_of_changes = self._sync_state.sync_info()
        if number_of_changes is None:
            self._trace('before whats_changed')
            new_gen, new_trans_id, changes = self._db.whats_changed(
                self.source_last_known_generation)
            self._trace('after whats_changed')
            seen_ids = self._sync_state.seen_ids()
            # changed docs that weren't superseded by or converged with
            changes_to_return = [
                (doc_id, gen, trans_id) for (doc_id, gen, trans_id) in changes
                # there was a subsequent update
                if doc_id not in seen_ids or seen_ids.get(doc_id) < gen]
            self._sync_state.put_changes_to_return(
                new_gen, new_trans_id, changes_to_return)
            number_of_changes = len(changes_to_return)
        # query server for stored changes
        _, _, next_change_to_return = \
            self._sync_state.next_change_to_return(received)
        self.new_gen = new_gen
        self.new_trans_id = new_trans_id
        # and append one change
        self.change_to_return = next_change_to_return
        return self.new_gen, number_of_changes

    def return_one_doc(self, return_doc_cb):
        """
        Return one changed document and its last change generation to the
        source syncing replica by invoking the callback return_doc_cb.

        This is called once for each document to be transferred from target to
        source.

        :param return_doc_cb: is a callback used to return the documents with
                              their last change generation to the target
                              replica.
        :type return_doc_cb: callable(doc, gen, trans_id)
        """
        if self.change_to_return is not None:
            changed_doc_id, gen, trans_id = self.change_to_return
            doc = self._db.get_doc(changed_doc_id, include_deleted=True)
            return_doc_cb(doc, gen, trans_id)

    def batched_insert_from_source(self, entries, sync_id):
        self._db.batch_start()
        for entry in entries:
            doc, gen, trans_id, number_of_docs, doc_idx = entry
            self.insert_doc_from_source(doc, gen, trans_id, number_of_docs,
                                        doc_idx, sync_id)
        self._db.batch_end()

    def insert_doc_from_source(
            self, doc, source_gen, trans_id,
            number_of_docs=None, doc_idx=None, sync_id=None):
        """Try to insert synced document from source.

        Conflicting documents are not inserted but will be sent over
        to the sync source.

        It keeps track of progress by storing the document source
        generation as well.

        The 1st step of a sync exchange is to call this repeatedly to
        try insert all incoming documents from the source.

        :param doc: A Document object.
        :type doc: Document
        :param source_gen: The source generation of doc.
        :type source_gen: int
        :param trans_id: The transaction id of that document change.
        :type trans_id: str
        :param number_of_docs: The total amount of documents sent on this sync
                               session.
        :type number_of_docs: int
        :param doc_idx: The index of the current document.
        :type doc_idx: int
        :param sync_id: The id of the current sync session.
        :type sync_id: str
        """
        state, at_gen = self._db._put_doc_if_newer(
            doc, save_conflict=False, replica_uid=self.source_replica_uid,
            replica_gen=source_gen, replica_trans_id=trans_id,
            number_of_docs=number_of_docs, doc_idx=doc_idx, sync_id=sync_id)
        if state == 'inserted':
            self._sync_state.put_seen_id(doc.doc_id, at_gen)
        elif state == 'converged':
            # magical convergence
            self._sync_state.put_seen_id(doc.doc_id, at_gen)
        elif state == 'superseded':
            # we have something newer that we will return
            pass
        else:
            # conflict that we will returne
            assert state == 'conflicted'


class SyncResource(http_app.SyncResource):

    max_request_size = MAX_REQUEST_SIZE * 1024 * 1024
    max_entry_size = MAX_ENTRY_SIZE * 1024 * 1024

    sync_exchange_class = SyncExchange

    @http_app.http_method(
        last_known_generation=int, last_known_trans_id=http_app.none_or_str,
        sync_id=http_app.none_or_str, content_as_args=True)
    def post_args(self, last_known_generation, last_known_trans_id=None,
                  sync_id=None, ensure=False):
        """
        Handle the initial arguments for the sync POST request from client.

        :param last_known_generation: The last server replica generation the
                                      client knows about.
        :type last_known_generation: int
        :param last_known_trans_id: The last server replica transaction_id the
                                    client knows about.
        :type last_known_trans_id: str
        :param sync_id: The id of the current sync session.
        :type sync_id: str
        :param ensure: Whether the server replica should be created if it does
                       not already exist.
        :type ensure: bool
        """
        # create or open the database
        cache = get_cache_for('db-' + sync_id + self.dbname, expire=120)
        if ensure:
            db, self.replica_uid = self.state.ensure_database(self.dbname)
        else:
            db = self.state.open_database(self.dbname)
        db.init_caching(cache)
        # validate the information the client has about server replica
        db.validate_gen_and_trans_id(
            last_known_generation, last_known_trans_id)
        # get a sync exchange object
        self.sync_exch = self.sync_exchange_class(
            db, self.source_replica_uid, last_known_generation, sync_id)
        self._sync_id = sync_id
        self._staging = []

    @http_app.http_method(content_as_args=True)
    def post_put(
            self, id, rev, content, gen,
            trans_id, number_of_docs, doc_idx):
        """
        Put one incoming document into the server replica.

        :param id: The id of the incoming document.
        :type id: str
        :param rev: The revision of the incoming document.
        :type rev: str
        :param content: The content of the incoming document.
        :type content: dict
        :param gen: The source replica generation corresponding to the
                    revision of the incoming document.
        :type gen: int
        :param trans_id: The source replica transaction id corresponding to
                         the revision of the incoming document.
        :type trans_id: str
        :param number_of_docs: The total amount of documents sent on this sync
                               session.
        :type number_of_docs: int
        :param doc_idx: The index of the current document.
        :type doc_idx: int
        """
        doc = Document(id, rev, content)
        self._staging.append((doc, gen, trans_id, number_of_docs, doc_idx))

    @http_app.http_method(received=int, content_as_args=True)
    def post_get(self, received):
        """
        Return one syncing document to the client.

        :param received: How many documents have already been received by the
                         client on the current sync session.
        :type received: int
        """

        def send_doc(doc, gen, trans_id):
            entry = dict(id=doc.doc_id, rev=doc.rev, content=doc.get_json(),
                         gen=gen, trans_id=trans_id)
            self.responder.stream_entry(entry)

        new_gen, number_of_changes = \
            self.sync_exch.find_changes_to_return(received)
        self.responder.content_type = 'application/x-u1db-sync-response'
        self.responder.start_response(200)
        self.responder.start_stream(),
        header = {
            "new_generation": new_gen,
            "new_transaction_id": self.sync_exch.new_trans_id,
            "number_of_changes": number_of_changes,
        }
        if self.replica_uid is not None:
            header['replica_uid'] = self.replica_uid
        self.responder.stream_entry(header)
        self.sync_exch.return_one_doc(send_doc)
        self.responder.end_stream()
        self.responder.finish_response()

    def post_end(self):
        """
        Return the current generation and transaction_id after inserting one
        incoming document.
        """
        self.sync_exch.batched_insert_from_source(self._staging, self._sync_id)
        self.responder.content_type = 'application/x-soledad-sync-response'
        self.responder.start_response(200)
        self.responder.start_stream(),
        new_gen, new_trans_id = self.sync_exch._db._get_generation_info()
        header = {
            "new_generation": new_gen,
            "new_transaction_id": new_trans_id,
        }
        if self.replica_uid is not None:
            header['replica_uid'] = self.replica_uid
        self.responder.stream_entry(header)
        self.responder.end_stream()
        self.responder.finish_response()
