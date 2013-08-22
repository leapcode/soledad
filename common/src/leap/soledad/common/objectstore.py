# -*- coding: utf-8 -*-
# objectstore.py
# Copyright (C) 2013 LEAP
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
Abstract U1DB backend to handle storage using object stores (like CouchDB, for
example).

Right now, this is only used by CouchDatabase backend, but can also be
extended to implement OpenStack or Amazon S3 storage, for example.

See U1DB documentation for more information on how to use databases.
"""


from u1db import errors
from u1db.backends.inmemory import (
    InMemoryDatabase,
    InMemorySyncTarget,
)


class ObjectStoreDatabase(InMemoryDatabase):
    """
    A backend for storing u1db data in an object store.
    """

    @classmethod
    def open_database(cls, url, create, document_factory=None):
        """
        Open a U1DB database using an object store as backend.

        @param url: the url of the database replica
        @type url: str
        @param create: should the replica be created if it does not exist?
        @type create: bool
        @param document_factory: A function that will be called with the same
            parameters as Document.__init__.
        @type document_factory: callable

        @return: the database instance
        @rtype: CouchDatabase
        """
        raise NotImplementedError(cls.open_database)

    def __init__(self, replica_uid=None, document_factory=None):
        """
        Initialize the object store database.

        @param replica_uid: an optional unique replica identifier
        @type replica_uid: str
        @param document_factory: A function that will be called with the same
            parameters as Document.__init__.
        @type document_factory: callable
        """
        InMemoryDatabase.__init__(
            self,
            replica_uid,
            document_factory=document_factory)
        # sync data in memory with data in object store
        if not self._get_doc(self.U1DB_DATA_DOC_ID):
            self._init_u1db_data()
        self._fetch_u1db_data()

    #-------------------------------------------------------------------------
    # methods from Database
    #-------------------------------------------------------------------------

    def _set_replica_uid(self, replica_uid):
        """
        Force the replica_uid to be set.

        @param replica_uid: The uid of the replica.
        @type replica_uid: str
        """
        InMemoryDatabase._set_replica_uid(self, replica_uid)
        self._store_u1db_data()

    def _put_doc(self, doc):
        """
        Update a document.

        This is called everytime we just want to do a raw put on the db (i.e.
        without index updates, document constraint checks, and conflict
        checks).

        @param doc: The document to update.
        @type doc: u1db.Document

        @return: The new revision identifier for the document.
        @rtype: str
        """
        raise NotImplementedError(self._put_doc)

    def _get_doc(self, doc_id):
        """
        Get just the document content, without fancy handling.

        @param doc_id: The unique document identifier
        @type doc_id: str
        @param include_deleted: If set to True, deleted documents will be
            returned with empty content. Otherwise asking for a deleted
            document will return None.
        @type include_deleted: bool

        @return: a Document object.
        @type: u1db.Document
        """
        raise NotImplementedError(self._get_doc)

    def get_all_docs(self, include_deleted=False):
        """
        Get the JSON content for all documents in the database.

        @param include_deleted: If set to True, deleted documents will be
            returned with empty content. Otherwise deleted documents will not
            be included in the results.
        @type include_deleted: bool

        @return: (generation, [Document])
            The current generation of the database, followed by a list of all
            the documents in the database.
        @rtype: tuple
        """
        raise NotImplementedError(self.get_all_docs)

    def delete_doc(self, doc):
        """
        Mark a document as deleted.

        @param doc: The document to mark as deleted.
        @type doc: u1db.Document

        @return: The new revision id of the document.
        @type: str
        """
        old_doc = self._get_doc(doc.doc_id, check_for_conflicts=True)
        if old_doc is None:
            raise errors.DocumentDoesNotExist
        if old_doc.rev != doc.rev:
            raise errors.RevisionConflict()
        if old_doc.is_tombstone():
            raise errors.DocumentAlreadyDeleted
        if old_doc.has_conflicts:
            raise errors.ConflictedDoc()
        new_rev = self._allocate_doc_rev(doc.rev)
        doc.rev = new_rev
        doc.make_tombstone()
        self._put_and_update_indexes(old_doc, doc)
        return new_rev

    # index-related methods

    def create_index(self, index_name, *index_expressions):
        """
        Create a named index, which can then be queried for future lookups.

        See U1DB documentation for more information.

        @param index_name: A unique name which can be used as a key prefix.
        @param index_expressions: Index expressions defining the index
            information.
        """
        raise NotImplementedError(self.create_index)

    def delete_index(self, index_name):
        """
        Remove a named index.

        Here we just guarantee that the new info will be stored in the backend
        db after update.

        @param index_name: The name of the index we are removing.
        @type index_name: str
        """
        InMemoryDatabase.delete_index(self, index_name)
        self._store_u1db_data()

    def _replace_conflicts(self, doc, conflicts):
        """
        Set new conflicts for a document.

        Here we just guarantee that the new info will be stored in the backend
        db after update.

        @param doc: The document with a new set of conflicts.
        @param conflicts: The new set of conflicts.
        @type conflicts: list
        """
        InMemoryDatabase._replace_conflicts(self, doc, conflicts)
        self._store_u1db_data()

    def _do_set_replica_gen_and_trans_id(self, other_replica_uid,
                                         other_generation,
                                         other_transaction_id):
        """
        Set the last-known generation and transaction id for the other
        database replica.

        Here we just guarantee that the new info will be stored in the backend
        db after update.

        @param other_replica_uid: The U1DB identifier for the other replica.
        @type other_replica_uid: str
        @param other_generation: The generation number for the other replica.
        @type other_generation: int
        @param other_transaction_id: The transaction id associated with the
            generation.
        @type other_transaction_id: str
        """
        InMemoryDatabase._do_set_replica_gen_and_trans_id(
            self,
            other_replica_uid,
            other_generation,
            other_transaction_id)
        self._store_u1db_data()

    #-------------------------------------------------------------------------
    # implemented methods from CommonBackend
    #-------------------------------------------------------------------------

    def _put_and_update_indexes(self, old_doc, doc):
        """
        Update a document and all indexes related to it.

        @param old_doc: The old version of the document.
        @type old_doc: u1db.Document
        @param doc: The new version of the document.
        @type doc: u1db.Document
        """
        for index in self._indexes.itervalues():
            if old_doc is not None and not old_doc.is_tombstone():
                index.remove_json(old_doc.doc_id, old_doc.get_json())
            if not doc.is_tombstone():
                index.add_json(doc.doc_id, doc.get_json())
        trans_id = self._allocate_transaction_id()
        self._put_doc(doc)
        self._transaction_log.append((doc.doc_id, trans_id))
        self._store_u1db_data()

    #-------------------------------------------------------------------------
    # methods specific for object stores
    #-------------------------------------------------------------------------

    U1DB_DATA_DOC_ID = 'u1db_data'

    def _fetch_u1db_data(self):
        """
        Fetch u1db configuration data from backend storage.

        See C{_init_u1db_data} documentation.
        """
        NotImplementedError(self._fetch_u1db_data)

    def _store_u1db_data(self):
        """
        Store u1db configuration data on backend storage.

        See C{_init_u1db_data} documentation.
        """
        NotImplementedError(self._store_u1db_data)

    def _init_u1db_data(self):
        """
        Initialize u1db configuration data on backend storage.

        A U1DB database needs to keep track of all database transactions,
        document conflicts, the generation of other replicas it has seen,
        indexes created by users and so on.

        In this implementation, all this information is stored in a special
        document stored in the couch db with id equals to
        CouchDatabse.U1DB_DATA_DOC_ID.

        This method initializes the document that will hold such information.
        """
        NotImplementedError(self._init_u1db_data)


class ObjectStoreSyncTarget(InMemorySyncTarget):
    """
    Functionality for using an ObjectStore as a synchronization target.
    """
