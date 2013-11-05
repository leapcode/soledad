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

import re
import simplejson as json
import socket
import logging


from u1db import errors
from u1db.sync import Synchronizer
from u1db.backends.inmemory import InMemoryIndex
from u1db.remote.server_state import ServerState
from u1db.errors import DatabaseDoesNotExist
from couchdb.client import Server, Document as CouchDocument
from couchdb.http import ResourceNotFound, Unauthorized


from leap.soledad.common import USER_DB_PREFIX
from leap.soledad.common.objectstore import (
    ObjectStoreDatabase,
    ObjectStoreSyncTarget,
)


logger = logging.getLogger(__name__)


class InvalidURLError(Exception):
    """
    Exception raised when Soledad encounters a malformed URL.
    """


def persistent_class(cls):
    """
    Decorator that modifies a class to ensure u1db metadata persists on
    underlying storage.

    @param cls: The class that will be modified.
    @type cls: type
    """

    def _create_persistent_method(old_method_name, key, load_method_name,
                                  dump_method_name, store):
        """
        Create a persistent method to replace C{old_method_name}.

        The new method will load C{key} using C{load_method_name} and stores
        it using C{dump_method_name} depending on the value of C{store}.
        """
        # get methods
        old_method = getattr(cls, old_method_name)
        load_method = getattr(cls, load_method_name) \
            if load_method_name is not None \
            else lambda self, data: setattr(self, key, data)
        dump_method = getattr(cls, dump_method_name) \
            if dump_method_name is not None \
            else lambda self: getattr(self, key)

        def _new_method(self, *args, **kwargs):
            # get u1db data from couch db
            doc = self._get_doc('%s%s' %
                                (self.U1DB_DATA_DOC_ID_PREFIX, key))
            load_method(self, doc.content['content'])
            # run old method
            retval = old_method(self, *args, **kwargs)
            # store u1db data on couch
            if store:
                doc.content = {'content': dump_method(self)}
                self._put_doc(doc)
            return retval

        return _new_method

    # ensure the class has a persistency map
    if not hasattr(cls, 'PERSISTENCY_MAP'):
        logger.error('Class %s has no PERSISTENCY_MAP attribute, skipping '
                     'persistent methods substitution.' % cls)
        return cls
    # replace old methods with new persistent ones
    for key, ((load_method_name, dump_method_name),
              persistent_methods) in cls.PERSISTENCY_MAP.iteritems():
        for (method_name, store) in persistent_methods:
            setattr(cls, method_name,
                    _create_persistent_method(
                        method_name,
                        key,
                        load_method_name,
                        dump_method_name,
                        store))
    return cls


@persistent_class
class CouchDatabase(ObjectStoreDatabase):
    """
    A U1DB backend that uses Couch as its persistence layer.
    """

    U1DB_TRANSACTION_LOG_KEY = '_transaction_log'
    U1DB_CONFLICTS_KEY = '_conflicts'
    U1DB_OTHER_GENERATIONS_KEY = '_other_generations'
    U1DB_INDEXES_KEY = '_indexes'
    U1DB_REPLICA_UID_KEY = '_replica_uid'

    U1DB_DATA_KEYS = [
        U1DB_TRANSACTION_LOG_KEY,
        U1DB_CONFLICTS_KEY,
        U1DB_OTHER_GENERATIONS_KEY,
        U1DB_INDEXES_KEY,
        U1DB_REPLICA_UID_KEY,
    ]

    COUCH_ID_KEY = '_id'
    COUCH_REV_KEY = '_rev'
    COUCH_U1DB_ATTACHMENT_KEY = 'u1db_json'
    COUCH_U1DB_REV_KEY = 'u1db_rev'

    # the following map describes information about methods usage of
    # properties that have to persist on the underlying database. The format
    # of the map is assumed to be:
    #
    #     {
    #         'property_name': [
    #             ('property_load_method_name', 'property_dump_method_name'),
    #             [('method_1_name', bool),
    #              ...
    #              ('method_N_name', bool)]],
    #         ...
    #     }
    #
    # where the booleans indicate if the property should be stored after
    # each method execution (i.e. if the method alters the property). Property
    # load/dump methods will be run after/before properties are read/written
    # to the underlying db.
    PERSISTENCY_MAP = {
        U1DB_TRANSACTION_LOG_KEY: [
            ('_load_transaction_log_from_json', None),
            [('_get_transaction_log', False),
             ('_get_generation', False),
             ('_get_generation_info', False),
             ('_get_trans_id_for_gen', False),
             ('whats_changed', False),
             ('_put_and_update_indexes', True)]],
        U1DB_CONFLICTS_KEY: [
            (None, None),
            [('_has_conflicts', False),
             ('get_doc_conflicts', False),
             ('_prune_conflicts', False),
             ('resolve_doc', False),
             ('_replace_conflicts', True),
             ('_force_doc_sync_conflict', True)]],
        U1DB_OTHER_GENERATIONS_KEY: [
            ('_load_other_generations_from_json', None),
            [('_get_replica_gen_and_trans_id', False),
             ('_do_set_replica_gen_and_trans_id', True)]],
        U1DB_INDEXES_KEY: [
            ('_load_indexes_from_json', '_dump_indexes_as_json'),
            [('list_indexes', False),
             ('get_from_index', False),
             ('get_range_from_index', False),
             ('get_index_keys', False),
             ('_put_and_update_indexes', True),
             ('create_index', True),
             ('delete_index', True)]],
        U1DB_REPLICA_UID_KEY: [
            (None, None),
            [('_allocate_doc_rev', False),
             ('_put_doc_if_newer', False),
             ('_ensure_maximal_rev', False),
             ('_prune_conflicts', False),
             ('_set_replica_uid', True)]]}

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
        # save params
        self._url = url
        self._full_commit = full_commit
        self._session = session
        # configure couch
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
            if doc_id.startswith(self.U1DB_DATA_DOC_ID_PREFIX):
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
            if doc_id.startswith(self.U1DB_DATA_DOC_ID_PREFIX):
                continue  # skip special files
            doc = self._get_doc(doc_id)
            if doc.content is not None:
                index.add_json(doc_id, doc.get_json())
        self._indexes[index_name] = index

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
        Initialize u1db configuration data on backend storage.

        A U1DB database needs to keep track of all database transactions,
        document conflicts, the generation of other replicas it has seen,
        indexes created by users and so on.

        In this implementation, all this information is stored in special
        documents stored in the underlying with doc_id prefix equal to
        U1DB_DATA_DOC_ID_PREFIX. Those documents ids are reserved: put_doc(),
        get_doc() and delete_doc() will not allow documents with a doc_id with
        that prefix to be accessed or modified.
        """
        for key in self.U1DB_DATA_KEYS:
            doc_id = '%s%s' % (self.U1DB_DATA_DOC_ID_PREFIX, key)
            doc = self._get_doc(doc_id)
            if doc is None:
                doc = self._factory(doc_id)
                doc.content = {'content': getattr(self, key)}
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
        Dump index definitions as JSON.
        """
        indexes = {}
        for name, idx in self._indexes.iteritems():
            indexes[name] = {}
            for attr in [self.INDEX_NAME_KEY, self.INDEX_DEFINITION_KEY,
                         self.INDEX_VALUES_KEY]:
                indexes[name][attr] = getattr(idx, '_' + attr)
        return indexes

    def _load_indexes_from_json(self, indexes):
        """
        Load index definitions from stored JSON.

        @param indexes: A JSON representation of indexes as
            [('index-name', ['field', 'field2', ...]), ...].
        @type indexes: str
        """
        self._indexes = {}
        for name, idx_dict in indexes.iteritems():
            idx = InMemoryIndex(name, idx_dict[self.INDEX_DEFINITION_KEY])
            idx._values = idx_dict[self.INDEX_VALUES_KEY]
            self._indexes[name] = idx

    def _load_transaction_log_from_json(self, transaction_log):
        """
        Load transaction log from stored JSON.

        @param transaction_log: A JSON representation of transaction_log as
            [('generation', 'transaction_id'), ...].
        @type transaction_log: list
        """
        self._transaction_log = []
        for gen, trans_id in transaction_log:
            self._transaction_log.append((gen, trans_id))

    def _load_other_generations_from_json(self, other_generations):
        """
        Load other generations from stored JSON.

        @param other_generations: A JSON representation of other_generations
            as {'replica_uid': ('generation', 'transaction_id'), ...}.
        @type other_generations: dict
        """
        self._other_generations = {}
        for replica_uid, [gen, trans_id] in other_generations.iteritems():
            self._other_generations[replica_uid] = (gen, trans_id)


class CouchSyncTarget(ObjectStoreSyncTarget):
    """
    Functionality for using a CouchDatabase as a synchronization target.
    """
    pass


class NotEnoughCouchPermissions(Exception):
    """
    Raised when failing to assert for enough permissions on underlying Couch
    Database.
    """
    pass


class CouchServerState(ServerState):
    """
    Inteface of the WSGI server with the CouchDB backend.
    """

    def __init__(self, couch_url, shared_db_name, tokens_db_name):
        """
        Initialize the couch server state.

        @param couch_url: The URL for the couch database.
        @type couch_url: str
        @param shared_db_name: The name of the shared database.
        @type shared_db_name: str
        @param tokens_db_name: The name of the tokens database.
        @type tokens_db_name: str
        """
        self._couch_url = couch_url
        self._shared_db_name = shared_db_name
        self._tokens_db_name = tokens_db_name
        try:
            self._check_couch_permissions()
        except NotEnoughCouchPermissions:
            logger.error("Not enough permissions on underlying couch "
                         "database (%s)." % self._couch_url)
        except (socket.error, socket.gaierror, socket.herror,
                socket.timeout), e:
            logger.error("Socket problem while trying to reach underlying "
                         "couch database: (%s, %s)." %
                         (self._couch_url, e))

    def _check_couch_permissions(self):
        """
        Assert that Soledad Server has enough permissions on the underlying
        couch database.

        Soledad Server has to be able to do the following in the couch server:

            * Create, read and write from/to 'shared' db.
            * Create, read and write from/to 'user-<anything>' dbs.
            * Read from 'tokens' db.

        This function tries to perform the actions above using the "low level"
        couch library to ensure that Soledad Server can do everything it needs
        on the underlying couch database.

        @param couch_url: The URL of the couch database.
        @type couch_url: str

        @raise NotEnoughCouchPermissions: Raised in case there are not enough
            permissions to read/write/create the needed couch databases.
        @rtype: bool
        """

        def _open_couch_db(dbname):
            server = Server(url=self._couch_url)
            try:
                server[dbname]
            except ResourceNotFound:
                server.create(dbname)
            return server[dbname]

        def _create_delete_test_doc(db):
            doc_id, _ = db.save({'test': 'document'})
            doc = db[doc_id]
            db.delete(doc)

        try:
            # test read/write auth for shared db
            _create_delete_test_doc(
                _open_couch_db(self._shared_db_name))
            # test read/write auth for user-<something> db
            _create_delete_test_doc(
                _open_couch_db('%stest-db' % USER_DB_PREFIX))
            # test read auth for tokens db
            tokensdb = _open_couch_db(self._tokens_db_name)
            tokensdb.info()
        except Unauthorized:
            raise NotEnoughCouchPermissions(self._couch_url)

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
