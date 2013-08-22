# -*- coding: utf-8 -*-
# couch.py
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


"""A U1DB backend that uses CouchDB as its persistence layer."""

import uuid
import re
import simplejson as json


from base64 import b64encode, b64decode
from u1db import errors
from u1db.sync import Synchronizer
from u1db.backends.inmemory import InMemoryIndex
from u1db.remote.server_state import ServerState
from u1db.errors import DatabaseDoesNotExist
from couchdb.client import Server, Document as CouchDocument
from couchdb.http import ResourceNotFound


from leap.soledad.common.objectstore import (
    ObjectStoreDatabase,
    ObjectStoreSyncTarget,
)


class InvalidURLError(Exception):
    """
    Exception raised when Soledad encounters a malformed URL.
    """


class CouchDatabase(ObjectStoreDatabase):
    """
    A U1DB backend that uses Couch as its persistence layer.
    """

    U1DB_TRANSACTION_LOG_KEY = 'transaction_log'
    U1DB_CONFLICTS_KEY = 'conflicts'
    U1DB_OTHER_GENERATIONS_KEY = 'other_generations'
    U1DB_INDEXES_KEY = 'indexes'
    U1DB_REPLICA_UID_KEY = 'replica_uid'

    COUCH_ID_KEY = '_id'
    COUCH_REV_KEY = '_rev'
    COUCH_U1DB_ATTACHMENT_KEY = 'u1db_json'
    COUCH_U1DB_REV_KEY = 'u1db_rev'

    @classmethod
    def open_database(cls, url, create):
        """
        Open a U1DB database using CouchDB as backend.

        @param url: the url of the database replica
        @type url: str
        @param create: should the replica be created if it does not exist?
        @type create: bool

        @return: the database instance
        @rtype: CouchDatabase
        """
        # get database from url
        m = re.match('(^https?://[^/]+)/(.+)$', url)
        if not m:
            raise InvalidURLError
        url = m.group(1)
        dbname = m.group(2)
        server = Server(url=url)
        try:
            server[dbname]
        except ResourceNotFound:
            if not create:
                raise DatabaseDoesNotExist()
        return cls(url, dbname)

    def __init__(self, url, dbname, replica_uid=None, full_commit=True,
                 session=None):
        """
        Create a new Couch data container.

        @param url: the url of the couch database
        @type url: str
        @param dbname: the database name
        @type dbname: str
        @param replica_uid: an optional unique replica identifier
        @type replica_uid: str
        @param full_commit: turn on the X-Couch-Full-Commit header
        @type full_commit: bool
        @param session: an http.Session instance or None for a default session
        @type session: http.Session
        """
        self._url = url
        self._full_commit = full_commit
        self._session = session
        self._server = Server(url=self._url,
                              full_commit=self._full_commit,
                              session=self._session)
        self._dbname = dbname
        # this will ensure that transaction and sync logs exist and are
        # up-to-date.
        try:
            self._database = self._server[self._dbname]
        except ResourceNotFound:
            self._server.create(self._dbname)
            self._database = self._server[self._dbname]
        ObjectStoreDatabase.__init__(self, replica_uid=replica_uid)

    #-------------------------------------------------------------------------
    # methods from Database
    #-------------------------------------------------------------------------

    def _get_doc(self, doc_id, check_for_conflicts=False):
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
        cdoc = self._database.get(doc_id)
        if cdoc is None:
            return None
        has_conflicts = False
        if check_for_conflicts:
            has_conflicts = self._has_conflicts(doc_id)
        doc = self._factory(
            doc_id=doc_id,
            rev=cdoc[self.COUCH_U1DB_REV_KEY],
            has_conflicts=has_conflicts)
        contents = self._database.get_attachment(
            cdoc,
            self.COUCH_U1DB_ATTACHMENT_KEY)
        if contents:
            doc.content = json.loads(contents.read())
        else:
            doc.make_tombstone()
        return doc

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
        generation = self._get_generation()
        results = []
        for doc_id in self._database:
            if doc_id == self.U1DB_DATA_DOC_ID:
                continue
            doc = self._get_doc(doc_id, check_for_conflicts=True)
            if doc.content is None and not include_deleted:
                continue
            results.append(doc)
        return (generation, results)

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
        # prepare couch's Document
        cdoc = CouchDocument()
        cdoc[self.COUCH_ID_KEY] = doc.doc_id
        # we have to guarantee that couch's _rev is consistent
        old_cdoc = self._database.get(doc.doc_id)
        if old_cdoc is not None:
            cdoc[self.COUCH_REV_KEY] = old_cdoc[self.COUCH_REV_KEY]
        # store u1db's rev
        cdoc[self.COUCH_U1DB_REV_KEY] = doc.rev
        # save doc in db
        self._database.save(cdoc)
        # store u1db's content as json string
        if not doc.is_tombstone():
            self._database.put_attachment(
                cdoc, doc.get_json(),
                filename=self.COUCH_U1DB_ATTACHMENT_KEY)
        else:
            self._database.delete_attachment(
                cdoc,
                self.COUCH_U1DB_ATTACHMENT_KEY)

    def get_sync_target(self):
        """
        Return a SyncTarget object, for another u1db to synchronize with.

        @return: The sync target.
        @rtype: CouchSyncTarget
        """
        return CouchSyncTarget(self)

    def create_index(self, index_name, *index_expressions):
        """
        Create a named index, which can then be queried for future lookups.

        @param index_name: A unique name which can be used as a key prefix.
        @param index_expressions: Index expressions defining the index
            information.
        """
        if index_name in self._indexes:
            if self._indexes[index_name]._definition == list(
                    index_expressions):
                return
            raise errors.IndexNameTakenError
        index = InMemoryIndex(index_name, list(index_expressions))
        for doc_id in self._database:
            if doc_id == self.U1DB_DATA_DOC_ID:  # skip special file
                continue
            doc = self._get_doc(doc_id)
            if doc.content is not None:
                index.add_json(doc_id, doc.get_json())
        self._indexes[index_name] = index
        # save data in object store
        self._store_u1db_data()

    def close(self):
        """
        Release any resources associated with this database.

        @return: True if db was succesfully closed.
        @rtype: bool
        """
        # TODO: fix this method so the connection is properly closed and
        # test_close (+tearDown, which deletes the db) works without problems.
        self._url = None
        self._full_commit = None
        self._session = None
        #self._server = None
        self._database = None
        return True

    def sync(self, url, creds=None, autocreate=True):
        """
        Synchronize documents with remote replica exposed at url.

        @param url: The url of the target replica to sync with.
        @type url: str
        @param creds: optional dictionary giving credentials.
            to authorize the operation with the server.
        @type creds: dict
        @param autocreate: Ask the target to create the db if non-existent.
        @type autocreate: bool

        @return: The local generation before the synchronisation was performed.
        @rtype: int
        """
        return Synchronizer(self, CouchSyncTarget(url, creds=creds)).sync(
            autocreate=autocreate)

    #-------------------------------------------------------------------------
    # methods from ObjectStoreDatabase
    #-------------------------------------------------------------------------

    def _init_u1db_data(self):
        """
        Initialize U1DB info data structure in the couch db.

        A U1DB database needs to keep track of all database transactions,
        document conflicts, the generation of other replicas it has seen,
        indexes created by users and so on.

        In this implementation, all this information is stored in a special
        document stored in the couch db with id equals to
        CouchDatabse.U1DB_DATA_DOC_ID.

        This method initializes the document that will hold such information.
        """
        if self._replica_uid is None:
            self._replica_uid = uuid.uuid4().hex
        # TODO: prevent user from overwriting a document with the same doc_id
        # as this one.
        doc = self._factory(doc_id=self.U1DB_DATA_DOC_ID)
        doc.content = {
            self.U1DB_TRANSACTION_LOG_KEY: b64encode(json.dumps([])),
            self.U1DB_CONFLICTS_KEY: b64encode(json.dumps({})),
            self.U1DB_OTHER_GENERATIONS_KEY: b64encode(json.dumps({})),
            self.U1DB_INDEXES_KEY: b64encode(json.dumps({})),
            self.U1DB_REPLICA_UID_KEY: b64encode(self._replica_uid),
        }
        self._put_doc(doc)

    def _fetch_u1db_data(self):
        """
        Fetch U1DB info from the couch db.

        See C{_init_u1db_data} documentation.
        """
        # retrieve u1db data from couch db
        cdoc = self._database.get(self.U1DB_DATA_DOC_ID)
        jsonstr = self._database.get_attachment(
            cdoc, self.COUCH_U1DB_ATTACHMENT_KEY).read()
        content = json.loads(jsonstr)
        # set u1db database info
        self._transaction_log = json.loads(
            b64decode(content[self.U1DB_TRANSACTION_LOG_KEY]))
        self._conflicts = json.loads(
            b64decode(content[self.U1DB_CONFLICTS_KEY]))
        self._other_generations = json.loads(
            b64decode(content[self.U1DB_OTHER_GENERATIONS_KEY]))
        self._indexes = self._load_indexes_from_json(
            b64decode(content[self.U1DB_INDEXES_KEY]))
        self._replica_uid = b64decode(content[self.U1DB_REPLICA_UID_KEY])
        # save couch _rev
        self._couch_rev = cdoc[self.COUCH_REV_KEY]

    def _store_u1db_data(self):
        """
        Store U1DB info in the couch db.

        See C{_init_u1db_data} documentation.
        """
        doc = self._factory(doc_id=self.U1DB_DATA_DOC_ID)
        doc.content = {
            # Here, the b64 encode ensures that document content
            # does not cause strange behaviour in couchdb because
            # of encoding.
            self.U1DB_TRANSACTION_LOG_KEY:
                b64encode(json.dumps(self._transaction_log)),
            self.U1DB_CONFLICTS_KEY: b64encode(json.dumps(self._conflicts)),
            self.U1DB_OTHER_GENERATIONS_KEY:
                b64encode(json.dumps(self._other_generations)),
            self.U1DB_INDEXES_KEY: b64encode(self._dump_indexes_as_json()),
            self.U1DB_REPLICA_UID_KEY: b64encode(self._replica_uid),
            self.COUCH_REV_KEY: self._couch_rev}
        self._put_doc(doc)

    #-------------------------------------------------------------------------
    # Couch specific methods
    #-------------------------------------------------------------------------

    INDEX_NAME_KEY = 'name'
    INDEX_DEFINITION_KEY = 'definition'
    INDEX_VALUES_KEY = 'values'

    def delete_database(self):
        """
        Delete a U1DB CouchDB database.
        """
        del(self._server[self._dbname])

    def _dump_indexes_as_json(self):
        """
        Dump index definitions as JSON string.
        """
        indexes = {}
        for name, idx in self._indexes.iteritems():
            indexes[name] = {}
            for attr in [self.INDEX_NAME_KEY, self.INDEX_DEFINITION_KEY,
                         self.INDEX_VALUES_KEY]:
                indexes[name][attr] = getattr(idx, '_' + attr)
        return json.dumps(indexes)

    def _load_indexes_from_json(self, indexes):
        """
        Load index definitions from JSON string.

        @param indexes: A JSON serialization of a list of [('index-name',
            ['field', 'field2'])].
        @type indexes: str

        @return: A dictionary with the index definitions.
        @rtype: dict
        """
        dict = {}
        for name, idx_dict in json.loads(indexes).iteritems():
            idx = InMemoryIndex(name, idx_dict[self.INDEX_DEFINITION_KEY])
            idx._values = idx_dict[self.INDEX_VALUES_KEY]
            dict[name] = idx
        return dict


class CouchSyncTarget(ObjectStoreSyncTarget):
    """
    Functionality for using a CouchDatabase as a synchronization target.
    """


class CouchServerState(ServerState):
    """
    Inteface of the WSGI server with the CouchDB backend.
    """

    def __init__(self, couch_url):
        self._couch_url = couch_url

    def open_database(self, dbname):
        """
        Open a couch database.

        @param dbname: The name of the database to open.
        @type dbname: str

        @return: The CouchDatabase object.
        @rtype: CouchDatabase
        """
        # TODO: open couch
        return CouchDatabase.open_database(
            self._couch_url + '/' + dbname,
            create=False)

    def ensure_database(self, dbname):
        """
        Ensure couch database exists.

        @param dbname: The name of the database to ensure.
        @type dbname: str

        @return: The CouchDatabase object and the replica uid.
        @rtype: (CouchDatabase, str)
        """
        db = CouchDatabase.open_database(
            self._couch_url + '/' + dbname,
            create=True)
        return db, db._replica_uid

    def delete_database(self, dbname):
        """
        Delete couch database.

        @param dbname: The name of the database to delete.
        @type dbname: str
        """
        CouchDatabase.delete_database(self._couch_url + '/' + dbname)

    def _set_couch_url(self, url):
        """
        Set the couchdb URL

        @param url: CouchDB URL
        @type url: str
        """
        self._couch_url = url

    def _get_couch_url(self):
        """
        Return CouchDB URL

        @rtype: str
        """
        return self._couch_url

    couch_url = property(_get_couch_url, _set_couch_url, doc='CouchDB URL')
