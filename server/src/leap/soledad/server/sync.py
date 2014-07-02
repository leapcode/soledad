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

import json


from leap.soledad.common.couch import CouchDatabase
from itertools import izip
from u1db import sync, Document
from u1db.remote import http_app


MAX_REQUEST_SIZE = 200  # in Mb
MAX_ENTRY_SIZE = 200  # in Mb


class ServerSyncState(object):
    """
    The state of one sync session, as stored on backend server.

    This object performes queries to distinct design documents:

        _design/syncs/_update/state
        _design/syncs/_view/state
        _design/syncs/_view/seen_ids
        _design/syncs/_view/changes_to_return

    On server side, the ongoing syncs metadata is maintained in a document
    called 'u1db_sync_state'.
    """

    def __init__(self, db, source_replica_uid, sync_id):
        """
        Initialize the sync state object.

        :param db: The target syncing database.
        :type db: CouchDatabase.
        :param source_replica_uid: CouchDatabase
        :type source_replica_uid: str
        """
        self._db = db
        self._source_replica_uid = source_replica_uid
        self._sync_id = sync_id

    def _key(self, key):
        """
        Format a key to be used on couch views.

        :param key: The lookup key.
        :type key: json serializable object

        :return: The properly formatted key.
        :rtype: str
        """
        return json.dumps(key, separators=(',', ':'))

    def _put_info(self, key, value):
        """
        Put some information on the sync state document.

        This method works in conjunction with the
        _design/syncs/_update/state update handler couch backend.

        :param key: The key for the info to be put.
        :type key: str
        :param value: The value for the info to be put.
        :type value: str
        """
        ddoc_path = [
            '_design', 'syncs', '_update', 'state',
            'u1db_sync_state']
        res = self._db._database.resource(*ddoc_path)
        with CouchDatabase.sync_info_lock[self._db.replica_uid]:
            res.put_json(
                body={
                    'sync_id': self._sync_id,
                    'source_replica_uid': self._source_replica_uid,
                    key: value,
                },
                headers={'content-type': 'application/json'})

    def put_seen_id(self, seen_id, gen):
        """
        Put one seen id on the sync state document.

        :param seen_id: The doc_id of a document seen during sync.
        :type seen_id: str
        :param gen: The corresponding db generation for that document.
        :type gen: int
        """
        self._put_info(
            'seen_id',
            [seen_id, gen])

    def seen_ids(self):
        """
        Return all document ids seen during the sync.

        :return: A list with doc ids seen during the sync.
        :rtype: list
        """
        ddoc_path = ['_design', 'syncs', '_view', 'seen_ids']
        resource = self._db._database.resource(*ddoc_path)
        response = resource.get_json(
            key=self._key([self._source_replica_uid, self._sync_id]))
        data = response[2]
        if data['rows']:
            entry = data['rows'].pop()
            return entry['value']['seen_ids']
        return []

    def put_changes_to_return(self, gen, trans_id, changes_to_return):
        """
        Put the calculated changes to return in the backend sync state
        document.

        :param gen: The target database generation that will be synced.
        :type gen: int
        :param trans_id: The target database transaction id that will be
                         synced.
        :type trans_id: str
        :param changes_to_return: A list of tuples with the changes to be
                                  returned during the sync process.
        :type changes_to_return: list
        """
        self._put_info(
            'changes_to_return',
            {
                'gen': gen,
                'trans_id': trans_id,
                'changes_to_return': changes_to_return,
            }
        )

    def sync_info(self):
        """
        Return information about the current sync state.

        :return: The generation and transaction id of the target database
                 which will be synced, and the number of documents to return,
                 or a tuple of Nones if those have not already been sent to
                 server.
        :rtype: tuple
        """
        ddoc_path = ['_design', 'syncs', '_view', 'state']
        resource = self._db._database.resource(*ddoc_path)
        response = resource.get_json(
            key=self._key([self._source_replica_uid, self._sync_id]))
        data = response[2]
        gen = None
        trans_id = None
        number_of_changes = None
        if data['rows'] and data['rows'][0]['value'] is not None:
            value = data['rows'][0]['value']
            gen = value['gen']
            trans_id = value['trans_id']
            number_of_changes = value['number_of_changes']
        return gen, trans_id, number_of_changes

    def next_change_to_return(self, received):
        """
        Return the next change to be returned to the source syncing replica.

        :param received: How many documents the source replica has already
                         received during the current sync process.
        :type received: int
        """
        ddoc_path = ['_design', 'syncs', '_view', 'changes_to_return']
        resource = self._db._database.resource(*ddoc_path)
        response = resource.get_json(
            key=self._key(
                [self._source_replica_uid, self._sync_id, received]))
        data = response[2]
        if not data['rows']:
            return None, None, None
        value = data['rows'][0]['value']
        gen = value['gen']
        trans_id = value['trans_id']
        next_change_to_return = value['next_change_to_return']
        return gen, trans_id, tuple(next_change_to_return)


class SyncExchange(sync.SyncExchange):

    def __init__(self, db, source_replica_uid, last_known_generation, sync_id):
        """
        :param db: The target syncing database.
        :type db: CouchDatabase
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
        self._sync_state = ServerSyncState(
            self._db, self.source_replica_uid, sync_id)


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

    def insert_doc_from_source(self, doc, source_gen, trans_id,
            number_of_docs=None, sync_id=None):
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
        :param sync_id: The id of the current sync session.
        :type sync_id: str
        """
        state, at_gen = self._db._put_doc_if_newer(
            doc, save_conflict=False, replica_uid=self.source_replica_uid,
            replica_gen=source_gen, replica_trans_id=trans_id,
            number_of_docs=number_of_docs, sync_id=sync_id)
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
        if ensure:
            db, self.replica_uid = self.state.ensure_database(self.dbname)
        else:
            db = self.state.open_database(self.dbname)
        # validate the information the client has about server replica
        db.validate_gen_and_trans_id(
            last_known_generation, last_known_trans_id)
        # get a sync exchange object
        self.sync_exch = self.sync_exchange_class(
            db, self.source_replica_uid, last_known_generation, sync_id)
        self._sync_id = sync_id

    @http_app.http_method(content_as_args=True)
    def post_put(self, id, rev, content, gen, trans_id, number_of_docs):
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
        """
        doc = Document(id, rev, content)
        self.sync_exch.insert_doc_from_source(
            doc, gen, trans_id, number_of_docs=number_of_docs,
            sync_id=self._sync_id)

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
