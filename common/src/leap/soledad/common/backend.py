# -*- coding: utf-8 -*-
# backend.py
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


"""A L2DB generic backend."""

import functools

from leap.soledad.common.document import ServerDocument
from leap.soledad.common.l2db import vectorclock
from leap.soledad.common.l2db.errors import (
    RevisionConflict,
    InvalidDocId,
    ConflictedDoc,
    DocumentDoesNotExist,
    DocumentAlreadyDeleted,
)
from leap.soledad.common.l2db.backends import CommonBackend
from leap.soledad.common.l2db.backends import CommonSyncTarget


class SoledadBackend(CommonBackend):
    BATCH_SUPPORT = False

    """
    A L2DB backend implementation.
    """

    def __init__(self, database, replica_uid=None):
        """
        Create a new backend.

        :param database: the database implementation
        :type database: Database
        :param replica_uid: an optional unique replica identifier
        :type replica_uid: str
        """
        # save params
        self._factory = ServerDocument
        self._real_replica_uid = None
        self._cache = None
        self._dbname = database._dbname
        self._database = database
        self.batching = False
        if replica_uid is not None:
            self._set_replica_uid(replica_uid)

    def batch_start(self):
        if not self.BATCH_SUPPORT:
            return
        self.batching = True
        self.after_batch_callbacks = {}
        self._database.batch_start()
        if not self._cache:
            # batching needs cache
            self._cache = {}
        self._get_generation()  # warm up gen info

    def batch_end(self):
        if not self.BATCH_SUPPORT:
            return
        self._database.batch_end()
        self.batching = False
        for name in self.after_batch_callbacks:
            self.after_batch_callbacks[name]()
        self.after_batch_callbacks = None

    @property
    def cache(self):
        if self._cache is not None:
            return self._cache
        else:
            return {}

    def init_caching(self, cache):
        """
        Start using cache by setting internal _cache attribute.

        :param cache: the cache instance, anything that behaves like a dict
        :type cache: dict
        """
        self._cache = cache

    def get_sync_target(self):
        """
        Return a SyncTarget object, for another u1db to synchronize with.

        :return: The sync target.
        :rtype: SoledadSyncTarget
        """
        return SoledadSyncTarget(self)

    def delete_database(self):
        """
        Delete a U1DB database.
        """
        self._database.delete_database()

    def close(self):
        """
        Release any resources associated with this database.

        :return: True if db was succesfully closed.
        :rtype: bool
        """
        self._database.close()
        return True

    def __del__(self):
        """
        Close the database upon garbage collection.
        """
        self.close()

    def _set_replica_uid(self, replica_uid):
        """
        Force the replica uid to be set.

        :param replica_uid: The new replica uid.
        :type replica_uid: str
        """
        self._database.set_replica_uid(replica_uid)
        self._real_replica_uid = replica_uid
        self.cache['replica_uid'] = self._real_replica_uid

    def _get_replica_uid(self):
        """
        Get the replica uid.

        :return: The replica uid.
        :rtype: str
        """
        if self._real_replica_uid is not None:
            self.cache['replica_uid'] = self._real_replica_uid
            return self._real_replica_uid
        if 'replica_uid' in self.cache:
            return self.cache['replica_uid']
        self._real_replica_uid = self._database.get_replica_uid()
        self._set_replica_uid(self._real_replica_uid)
        return self._real_replica_uid

    _replica_uid = property(_get_replica_uid, _set_replica_uid)

    replica_uid = property(_get_replica_uid)

    def _get_generation(self):
        """
        Return the current generation.

        :return: The current generation.
        :rtype: int

        :raise SoledadError: Raised by database on operation failure
        """
        return self._get_generation_info()[0]

    def _get_generation_info(self):
        """
        Return the current generation.

        :return: A tuple containing the current generation and transaction id.
        :rtype: (int, str)

        :raise SoledadError: Raised by database on operation failure
        """
        cur_gen, newest_trans_id = self._database.get_generation_info()
        return (cur_gen, newest_trans_id)

    def _get_trans_id_for_gen(self, generation):
        """
        Get the transaction id corresponding to a particular generation.

        :param generation: The generation for which to get the transaction id.
        :type generation: int

        :return: The transaction id for C{generation}.
        :rtype: str

        :raise InvalidGeneration: Raised when the generation does not exist.

        """
        return self._database.get_trans_id_for_gen(generation)

    def _get_transaction_log(self):
        """
        This is only for the test suite, it is not part of the api.

        :return: The complete transaction log.
        :rtype: [(str, str)]

        """
        return self._database.get_transaction_log()

    def _get_doc(self, doc_id, check_for_conflicts=False):
        """
        Extract the document from storage.

        This can return None if the document doesn't exist.

        :param doc_id: The unique document identifier
        :type doc_id: str
        :param check_for_conflicts: If set to False, then the conflict check
                                    will be skipped.
        :type check_for_conflicts: bool

        :return: The document.
        :rtype: ServerDocument
        """
        return self._database.get_doc(doc_id, check_for_conflicts)

    def get_doc(self, doc_id, include_deleted=False):
        """
        Get the JSON string for the given document.

        :param doc_id: The unique document identifier
        :type doc_id: str
        :param include_deleted: If set to True, deleted documents will be
            returned with empty content. Otherwise asking for a deleted
            document will return None.
        :type include_deleted: bool

        :return: A document object.
        :rtype: ServerDocument.
        """
        doc = self._get_doc(doc_id, check_for_conflicts=True)
        if doc is None:
            return None
        if doc.is_tombstone() and not include_deleted:
            return None
        return doc

    def get_all_docs(self, include_deleted=False):
        """
        Get the JSON content for all documents in the database.

        :param include_deleted: If set to True, deleted documents will be
                                returned with empty content. Otherwise deleted
                                documents will not be included in the results.
        :type include_deleted: bool

        :return: (generation, [ServerDocument])
            The current generation of the database, followed by a list of all
            the documents in the database.
        :rtype: (int, [ServerDocument])
        """
        return self._database.get_all_docs(include_deleted)

    def _put_doc(self, old_doc, doc):
        """
        Put the document in the backend database.

        Note that C{old_doc} must have been fetched with the parameter
        C{check_for_conflicts} equal to True, so we can properly update the
        new document using the conflict information from the old one.

        :param old_doc: The old document version.
        :type old_doc: ServerDocument
        :param doc: The document to be put.
        :type doc: ServerDocument
        """
        self._database.save_document(old_doc, doc,
                                     self._allocate_transaction_id())

    def put_doc(self, doc):
        """
        Update a document.

        If the document currently has conflicts, put will fail.
        If the database specifies a maximum document size and the document
        exceeds it, put will fail and raise a DocumentTooBig exception.

        :param doc: A Document with new content.
        :return: new_doc_rev - The new revision identifier for the document.
            The Document object will also be updated.

        :raise InvalidDocId: Raised if the document's id is invalid.
        :raise DocumentTooBig: Raised if the document size is too big.
        :raise ConflictedDoc: Raised if the document has conflicts.
        """
        if doc.doc_id is None:
            raise InvalidDocId()
        self._check_doc_id(doc.doc_id)
        self._check_doc_size(doc)
        old_doc = self._get_doc(doc.doc_id, check_for_conflicts=True)
        if old_doc and old_doc.has_conflicts:
            raise ConflictedDoc()
        if old_doc and doc.rev is None and old_doc.is_tombstone():
            new_rev = self._allocate_doc_rev(old_doc.rev)
        else:
            if old_doc is not None:
                    if old_doc.rev != doc.rev:
                        raise RevisionConflict()
            else:
                if doc.rev is not None:
                    raise RevisionConflict()
            new_rev = self._allocate_doc_rev(doc.rev)
        doc.rev = new_rev
        self._put_doc(old_doc, doc)
        return new_rev

    def whats_changed(self, old_generation=0):
        """
        Return a list of documents that have changed since old_generation.

        :param old_generation: The generation of the database in the old
                               state.
        :type old_generation: int

        :return: (generation, trans_id, [(doc_id, generation, trans_id),...])
                 The current generation of the database, its associated
                 transaction id, and a list of of changed documents since
                 old_generation, represented by tuples with for each document
                 its doc_id and the generation and transaction id corresponding
                 to the last intervening change and sorted by generation (old
                 changes first)
        :rtype: (int, str, [(str, int, str)])
        """
        return self._database.whats_changed(old_generation)

    def delete_doc(self, doc):
        """
        Mark a document as deleted.

        Will abort if the current revision doesn't match doc.rev.
        This will also set doc.content to None.

        :param doc: The document to mark as deleted.
        :type doc: ServerDocument.

        :raise DocumentDoesNotExist: Raised if the document does not
                                            exist.
        :raise RevisionConflict: Raised if the revisions do not match.
        :raise DocumentAlreadyDeleted: Raised if the document is
                                              already deleted.
        :raise ConflictedDoc: Raised if the doc has conflicts.
        """
        old_doc = self._get_doc(doc.doc_id, check_for_conflicts=True)
        if old_doc is None:
            raise DocumentDoesNotExist
        if old_doc.rev != doc.rev:
            raise RevisionConflict()
        if old_doc.is_tombstone():
            raise DocumentAlreadyDeleted
        if old_doc.has_conflicts:
            raise ConflictedDoc()
        new_rev = self._allocate_doc_rev(doc.rev)
        doc.rev = new_rev
        doc.make_tombstone()
        self._put_doc(old_doc, doc)
        return new_rev

    def get_doc_conflicts(self, doc_id):
        """
        Get the conflicted versions of a document.

        :param doc_id: The document id.
        :type doc_id: str

        :return: A list of conflicted versions of the document.
        :rtype: list
        """
        return self._database.get_doc_conflicts(doc_id)

    def _get_replica_gen_and_trans_id(self, other_replica_uid):
        """
        Return the last known generation and transaction id for the other db
        replica.

        When you do a synchronization with another replica, the Database keeps
        track of what generation the other database replica was at, and what
        the associated transaction id was.  This is used to determine what data
        needs to be sent, and if two databases are claiming to be the same
        replica.

        :param other_replica_uid: The identifier for the other replica.
        :type other_replica_uid: str

        :return: A tuple containing the generation and transaction id we
                 encountered during synchronization. If we've never
                 synchronized with the replica, this is (0, '').
        :rtype: (int, str)
        """
        if other_replica_uid in self.cache:
            return self.cache[other_replica_uid]
        gen, trans_id = \
            self._database.get_replica_gen_and_trans_id(other_replica_uid)
        self.cache[other_replica_uid] = (gen, trans_id)
        return (gen, trans_id)

    def _set_replica_gen_and_trans_id(self, other_replica_uid,
                                      other_generation, other_transaction_id):
        """
        Set the last-known generation and transaction id for the other
        database replica.

        We have just performed some synchronization, and we want to track what
        generation the other replica was at. See also
        _get_replica_gen_and_trans_id.

        :param other_replica_uid: The U1DB identifier for the other replica.
        :type other_replica_uid: str
        :param other_generation: The generation number for the other replica.
        :type other_generation: int
        :param other_transaction_id: The transaction id associated with the
            generation.
        :type other_transaction_id: str
        """
        if other_replica_uid is not None and other_generation is not None:
            self.cache[other_replica_uid] = (other_generation,
                                             other_transaction_id)
            self._database.set_replica_gen_and_trans_id(other_replica_uid,
                                                        other_generation,
                                                        other_transaction_id)

    def _do_set_replica_gen_and_trans_id(
            self, other_replica_uid, other_generation, other_transaction_id):
        """
        _put_doc_if_newer from super class is calling it. So we declare this.

        :param other_replica_uid: The U1DB identifier for the other replica.
        :type other_replica_uid: str
        :param other_generation: The generation number for the other replica.
        :type other_generation: int
        :param other_transaction_id: The transaction id associated with the
                                     generation.
        :type other_transaction_id: str
        """
        args = [other_replica_uid, other_generation, other_transaction_id]
        callback = functools.partial(self._set_replica_gen_and_trans_id, *args)
        if self.batching:
            self.after_batch_callbacks['set_source_info'] = callback
        else:
            callback()

    def _force_doc_sync_conflict(self, doc):
        """
        Add a conflict and force a document put.

        :param doc: The document to be put.
        :type doc: ServerDocument
        """
        my_doc = self._get_doc(doc.doc_id)
        self._prune_conflicts(doc, vectorclock.VectorClockRev(doc.rev))
        doc.add_conflict(self._factory(doc.doc_id, my_doc.rev,
                                       my_doc.get_json()))
        doc.has_conflicts = True
        self._put_doc(my_doc, doc)

    def resolve_doc(self, doc, conflicted_doc_revs):
        """
        Mark a document as no longer conflicted.

        We take the list of revisions that the client knows about that it is
        superseding. This may be a different list from the actual current
        conflicts, in which case only those are removed as conflicted.  This
        may fail if the conflict list is significantly different from the
        supplied information. (sync could have happened in the background from
        the time you GET_DOC_CONFLICTS until the point where you RESOLVE)

        :param doc: A Document with the new content to be inserted.
        :type doc: ServerDocument
        :param conflicted_doc_revs: A list of revisions that the new content
                                    supersedes.
        :type conflicted_doc_revs: [str]

        :raise SoledadError: Raised by database on operation failure
        """
        cur_doc = self._get_doc(doc.doc_id, check_for_conflicts=True)
        new_rev = self._ensure_maximal_rev(cur_doc.rev,
                                           conflicted_doc_revs)
        superseded_revs = set(conflicted_doc_revs)
        doc.rev = new_rev
        # this backend stores conflicts as properties of the documents, so we
        # have to copy these conflicts over to the document being updated.
        if cur_doc.rev in superseded_revs:
            # the newer doc version will supersede the one in the database, so
            # we copy conflicts before updating the backend.
            doc.set_conflicts(cur_doc.get_conflicts())  # copy conflicts over.
            doc.delete_conflicts(superseded_revs)
            self._put_doc(cur_doc, doc)
        else:
            # the newer doc version does not supersede the one in the
            # database, so we will add a conflict to the database and copy
            # those over to the document the user has in her hands.
            cur_doc.add_conflict(doc)
            cur_doc.delete_conflicts(superseded_revs)
            self._put_doc(cur_doc, cur_doc)  # just update conflicts
            # backend has been updated with current conflicts, now copy them
            # to the current document.
            doc.set_conflicts(cur_doc.get_conflicts())

    def _put_doc_if_newer(self, doc, save_conflict, replica_uid, replica_gen,
                          replica_trans_id='', number_of_docs=None,
                          doc_idx=None, sync_id=None):
        """
        Insert/update document into the database with a given revision.

        This api is used during synchronization operations.

        If a document would conflict and save_conflict is set to True, the
        content will be selected as the 'current' content for doc.doc_id,
        even though doc.rev doesn't supersede the currently stored revision.
        The currently stored document will be added to the list of conflict
        alternatives for the given doc_id.

        This forces the new content to be 'current' so that we get convergence
        after synchronizing, even if people don't resolve conflicts. Users can
        then notice that their content is out of date, update it, and
        synchronize again. (The alternative is that users could synchronize and
        think the data has propagated, but their local copy looks fine, and the
        remote copy is never updated again.)

        :param doc: A document object
        :type doc: ServerDocument
        :param save_conflict: If this document is a conflict, do you want to
                              save it as a conflict, or just ignore it.
        :type save_conflict: bool
        :param replica_uid: A unique replica identifier.
        :type replica_uid: str
        :param replica_gen: The generation of the replica corresponding to the
                            this document. The replica arguments are optional,
                            but are used during synchronization.
        :type replica_gen: int
        :param replica_trans_id: The transaction_id associated with the
                                 generation.
        :type replica_trans_id: str
        :param number_of_docs: The total amount of documents sent on this sync
                               session.
        :type number_of_docs: int
        :param doc_idx: The index of the current document being sent.
        :type doc_idx: int
        :param sync_id: The id of the current sync session.
        :type sync_id: str

        :return: (state, at_gen) -  If we don't have doc_id already, or if
                 doc_rev supersedes the existing document revision, then the
                 content will be inserted, and state is 'inserted'.  If
                 doc_rev is less than or equal to the existing revision, then
                 the put is ignored and state is respecitvely 'superseded' or
                 'converged'.  If doc_rev is not strictly superseded or
                 supersedes, then state is 'conflicted'. The document will not
                 be inserted if save_conflict is False.  For 'inserted' or
                 'converged', at_gen is the insertion/current generation.
        :rtype: (str, int)
        """
        if not isinstance(doc, ServerDocument):
            doc = self._factory(doc.doc_id, doc.rev, doc.get_json())
        my_doc = self._get_doc(doc.doc_id, check_for_conflicts=True)
        if my_doc:
            doc.set_conflicts(my_doc.get_conflicts())
        return CommonBackend._put_doc_if_newer(self, doc, save_conflict,
                                               replica_uid, replica_gen,
                                               replica_trans_id)

    def _put_and_update_indexes(self, cur_doc, doc):
        self._put_doc(cur_doc, doc)

    def get_docs(self, doc_ids, check_for_conflicts=True,
                 include_deleted=False, read_content=True):
        """
        Get the JSON content for many documents.

        :param doc_ids: A list of document identifiers or None for all.
        :type doc_ids: list
        :param check_for_conflicts: If set to False, then the conflict check
                                    will be skipped, and 'None' will be
                                    returned instead of True/False.
        :type check_for_conflicts: bool
        :param include_deleted: If set to True, deleted documents will be
                                returned with empty content. Otherwise deleted
                                documents will not be included in the results.
        :return: iterable giving the Document object for each document id
                 in matching doc_ids order.
        :rtype: iterable
        """
        return self._database.get_docs(doc_ids, check_for_conflicts,
                                       include_deleted, read_content)

    def _prune_conflicts(self, doc, doc_vcr):
        """
        Prune conflicts that are older then the current document's revision, or
        whose content match to the current document's content.
        Originally in u1db.CommonBackend

        :param doc: The document to have conflicts pruned.
        :type doc: ServerDocument
        :param doc_vcr: A vector clock representing the current document's
                        revision.
        :type doc_vcr: u1db.vectorclock.VectorClock
        """
        if doc.has_conflicts:
            autoresolved = False
            c_revs_to_prune = []
            for c_doc in doc._conflicts:
                c_vcr = vectorclock.VectorClockRev(c_doc.rev)
                if doc_vcr.is_newer(c_vcr):
                    c_revs_to_prune.append(c_doc.rev)
                elif doc.same_content_as(c_doc):
                    c_revs_to_prune.append(c_doc.rev)
                    doc_vcr.maximize(c_vcr)
                    autoresolved = True
            if autoresolved:
                doc_vcr.increment(self._replica_uid)
                doc.rev = doc_vcr.as_str()
            doc.delete_conflicts(c_revs_to_prune)


class SoledadSyncTarget(CommonSyncTarget):

    """
    Functionality for using a SoledadBackend as a synchronization target.
    """

    def get_sync_info(self, source_replica_uid):
        source_gen, source_trans_id = self._db._get_replica_gen_and_trans_id(
            source_replica_uid)
        my_gen, my_trans_id = self._db._get_generation_info()
        return (
            self._db._replica_uid, my_gen, my_trans_id, source_gen,
            source_trans_id)

    def record_sync_info(self, source_replica_uid, source_replica_generation,
                         source_replica_transaction_id):
        if self._trace_hook:
            self._trace_hook('record_sync_info')
        self._db._set_replica_gen_and_trans_id(
            source_replica_uid, source_replica_generation,
            source_replica_transaction_id)
