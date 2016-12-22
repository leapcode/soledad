# -*- coding: utf-8 -*-
# __init__.py
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


"""A U1DB backend that uses CouchDB as its persistence layer."""


import json
import copy
import re
import uuid
import binascii


from StringIO import StringIO
from urlparse import urljoin
from contextlib import contextmanager


from couchdb.client import Server, Database
from couchdb.http import (
    ResourceConflict,
    ResourceNotFound,
    Session,
    urljoin as couch_urljoin,
    Resource,
)
from leap.soledad.common.l2db.errors import (
    DatabaseDoesNotExist,
    InvalidGeneration,
    RevisionConflict,
)
from leap.soledad.common.l2db.remote import http_app


from .support import MultipartWriter
from leap.soledad.common.errors import InvalidURLError
from leap.soledad.common.document import ServerDocument
from leap.soledad.common.backend import SoledadBackend


COUCH_TIMEOUT = 120  # timeout for transfers between Soledad server and Couch


def list_users_dbs(couch_url):
    """
    Retrieves a list with all databases that starts with 'user-' on CouchDB.
    Those databases belongs to users. So, the list will contain all the
    database names in the form of 'user-{uuid4}'.

    :param couch_url: The couch url with needed credentials
    :type couch_url: str

    :return: The list of all database names from users.
    :rtype: [str]
    """
    with couch_server(couch_url) as server:
        users = [dbname for dbname in server if dbname.startswith('user-')]
    return users


# monkey-patch the u1db http app to use ServerDocument
http_app.Document = ServerDocument


@contextmanager
def couch_server(url):
    """
    Provide a connection to a couch server and cleanup after use.

    For database creation and deletion we use an ephemeral connection to the
    couch server. That connection has to be properly closed, so we provide it
    as a context manager.

    :param url: The URL of the Couch server.
    :type url: str
    """
    session = Session(timeout=COUCH_TIMEOUT)
    server = Server(url=url, full_commit=False, session=session)
    yield server


def _get_gen_doc_id(gen):
    return 'gen-%s' % str(gen).zfill(10)


GENERATION_KEY = 'gen'
TRANSACTION_ID_KEY = 'trans_id'
REPLICA_UID_KEY = 'replica_uid'
DOC_ID_KEY = 'doc_id'
SCHEMA_VERSION_KEY = 'schema_version'

CONFIG_DOC_ID = '_local/config'
SYNC_DOC_ID_PREFIX = '_local/sync_'
SCHEMA_VERSION = 1


class CouchDatabase(object):
    """
    Holds CouchDB related code.
    This class gives methods to encapsulate database operations and hide
    CouchDB details from backend code.
    """

    @classmethod
    def open_database(cls, url, create, replica_uid=None,
                      database_security=None):
        """
        Open a U1DB database using CouchDB as backend.

        :param url: the url of the database replica
        :type url: str
        :param create: should the replica be created if it does not exist?
        :type create: bool
        :param replica_uid: an optional unique replica identifier
        :type replica_uid: str
        :param database_security: security rules as CouchDB security doc
        :type database_security: dict

        :return: the database instance
        :rtype: SoledadBackend

        :raise DatabaseDoesNotExist: Raised if database does not exist.
        """
        # get database from url
        m = re.match('(^https?://[^/]+)/(.+)$', url)
        if not m:
            raise InvalidURLError
        url = m.group(1)
        dbname = m.group(2)
        with couch_server(url) as server:
            if dbname not in server:
                if create:
                    server.create(dbname)
                else:
                    raise DatabaseDoesNotExist()
        db = cls(url, dbname, ensure_security=create,
                 database_security=database_security)
        return SoledadBackend(
            db, replica_uid=replica_uid)

    def __init__(self, url, dbname, ensure_security=False,
                 database_security=None):
        """
        :param url: Couch server URL with necessary credentials
        :type url: string
        :param dbname: Couch database name
        :type dbname: string
        :param ensure_security: will PUT a _security ddoc if set
        :type ensure_security: bool
        :param database_security: security rules as CouchDB security doc
        :type database_security: dict
        """
        self._session = Session(timeout=COUCH_TIMEOUT)
        self._url = url
        self._dbname = dbname
        self._database = self.get_couch_database(url, dbname)
        self.batching = False
        self.batch_generation = None
        self.batch_docs = {}
        if ensure_security:
            self.ensure_security_ddoc(database_security)

    def batch_start(self):
        self.batching = True
        self.batch_generation = self.get_generation_info()
        ids = set(row.id for row in self._database.view('_all_docs'))
        self.batched_ids = ids

    def batch_end(self):
        self.batching = False
        self.batch_generation = None
        self.__perform_batch()

    def get_couch_database(self, url, dbname):
        """
        Generate a couchdb.Database instance given a url and dbname.

        :param url: CouchDB's server url with credentials
        :type url: str
        :param dbname: Database name
        :type dbname: str

        :return: couch library database instance
        :rtype: couchdb.Database

        :raise DatabaseDoesNotExist: Raised if database does not exist.
        """
        try:
            return Database(
                urljoin(url, dbname),
                self._session)
        except ResourceNotFound:
            raise DatabaseDoesNotExist()

    def ensure_security_ddoc(self, security_config=None):
        """
        Make sure that only soledad user is able to access this database as
        an unprivileged member, meaning that administration access will
        be forbidden even inside an user database.
        The goal is to make sure that only the lowest access level is given
        to the unprivileged CouchDB user set on the server process.
        This is achieved by creating a _security design document, see:
        http://docs.couchdb.org/en/latest/api/database/security.html

        :param security_config: security configuration parsed from conf file
        :type security_config: dict
        """
        security_config = security_config or {}
        security = self._database.resource.get_json('_security')[2]
        security['members'] = {'names': [], 'roles': []}
        security['members']['names'] = security_config.get('members',
                                                           ['soledad'])
        security['members']['roles'] = security_config.get('members_roles', [])
        security['admins'] = {'names': [], 'roles': []}
        security['admins']['names'] = security_config.get('admins', [])
        security['admins']['roles'] = security_config.get('admins_roles', [])
        self._database.resource.put_json('_security', body=security)

    def delete_database(self):
        """
        Delete a U1DB CouchDB database.
        """
        with couch_server(self._url) as server:
            del(server[self._dbname])

    def set_replica_uid(self, replica_uid):
        """
        Force the replica uid to be set.

        :param replica_uid: The new replica uid.
        :type replica_uid: str
        """
        try:
            # set on existent config document
            doc = self._database[CONFIG_DOC_ID]
            doc[REPLICA_UID_KEY] = replica_uid
        except ResourceNotFound:
            # or create the config document
            doc = {
                '_id': CONFIG_DOC_ID,
                REPLICA_UID_KEY: replica_uid,
                SCHEMA_VERSION_KEY: SCHEMA_VERSION,
            }
        self._database.save(doc)

    def get_replica_uid(self):
        """
        Get the replica uid.

        :return: The replica uid.
        :rtype: str
        """
        try:
            # grab replica_uid from server
            doc = self._database[CONFIG_DOC_ID]
            replica_uid = doc[REPLICA_UID_KEY]
            return replica_uid
        except ResourceNotFound:
            # create a unique replica_uid
            replica_uid = uuid.uuid4().hex
            self.set_replica_uid(replica_uid)
            return replica_uid

    def close(self):
        self._database = None

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

        generation, _ = self.get_generation_info()
        results = list(
            self.get_docs(None, True, include_deleted))
        return (generation, results)

    def get_docs(self, doc_ids, check_for_conflicts=True,
                 include_deleted=False, read_content=True):
        """
        Get the JSON content for many documents.

        Use couch's `_all_docs` view to get the documents indicated in
        `doc_ids`,

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
        params = {'include_docs': 'true', 'attachments': 'false'}
        if doc_ids is not None:
            params['keys'] = doc_ids
        view = self._database.view("_all_docs", **params)
        for row in view.rows:
            result = copy.deepcopy(row['doc'])
            for file_name in result.get('_attachments', {}).keys():
                data = self._database.get_attachment(result, file_name)
                if data:
                    if read_content:
                        data = data.read()
                    result['_attachments'][file_name] = {'data': data}
            doc = self.__parse_doc_from_couch(
                result, result['_id'],
                check_for_conflicts=check_for_conflicts, decode=False)
            # filter out non-u1db or deleted documents
            if not doc or (not include_deleted and doc.is_tombstone()):
                continue
            yield doc

    def get_doc(self, doc_id, check_for_conflicts=False):
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
        doc_from_batch = self.__check_batch_before_get(doc_id)
        if doc_from_batch:
            return doc_from_batch
        if self.batching and doc_id not in self.batched_ids:
            return None
        if doc_id not in self._database:
            return None
        # get document with all attachments (u1db content and eventual
        # conflicts)
        result = self.json_from_resource([doc_id], attachments=True)
        return self.__parse_doc_from_couch(result, doc_id, check_for_conflicts)

    def __check_batch_before_get(self, doc_id):
        """
        If doc_id is staged for batching, then we need to commit the batch
        before going ahead. This avoids consistency problems, like trying to
        get a document that isn't persisted and processing like it is missing.

        :param doc_id: The unique document identifier
        :type doc_id: str
        """
        if doc_id in self.batch_docs:
            couch_doc = self.batch_docs[doc_id]
            rev = self.__perform_batch(doc_id)
            couch_doc['_rev'] = rev
            self.batched_ids.add(doc_id)
            return self.__parse_doc_from_couch(couch_doc, doc_id, True)
        return None

    def __perform_batch(self, doc_id=None):
        status = self._database.update(self.batch_docs.values())
        rev = None
        for ok, stored_doc_id, rev_or_error in status:
            if not ok:
                error = rev_or_error
                if type(error) is ResourceConflict:
                    raise RevisionConflict
                raise error
            elif doc_id == stored_doc_id:
                rev = rev_or_error
        self.batch_docs.clear()
        return rev

    def __parse_doc_from_couch(self, result, doc_id,
                               check_for_conflicts=False, decode=True):
        # restrict to u1db documents
        if 'u1db_rev' not in result:
            return None
        doc = ServerDocument(doc_id, result['u1db_rev'])
        # set contents or make tombstone
        if '_attachments' not in result \
                or 'u1db_content' not in result['_attachments']:
            doc.make_tombstone()
        elif decode:
            doc.content = json.loads(
                binascii.a2b_base64(
                    result['_attachments']['u1db_content']['data']))
        else:
            doc._json = result['_attachments']['u1db_content']['data']
        # determine if there are conflicts
        if check_for_conflicts \
                and '_attachments' in result \
                and 'u1db_conflicts' in result['_attachments']:
            if decode:
                conflicts = binascii.a2b_base64(
                    result['_attachments']['u1db_conflicts']['data'])
            else:
                conflicts = result['_attachments']['u1db_conflicts']['data']
            conflicts = json.loads(conflicts)
            doc.set_conflicts(self._build_conflicts(doc.doc_id, conflicts))
        # store couch revision
        doc.couch_rev = result['_rev']
        return doc

    def _build_conflicts(self, doc_id, attached_conflicts):
        """
        Build the conflicted documents list from the conflicts attachment
        fetched from a couch document.

        :param attached_conflicts: The document's conflicts as fetched from a
                                   couch document attachment.
        :type attached_conflicts: dict
        """
        conflicts = []
        for doc_rev, content in attached_conflicts:
            doc = ServerDocument(doc_id, doc_rev)
            if content is None:
                doc.make_tombstone()
            else:
                doc.content = content
            conflicts.append(doc)
        return conflicts

    def get_trans_id_for_gen(self, generation):
        """
        Get the transaction id corresponding to a particular generation.

        :param generation: The generation for which to get the transaction id.
        :type generation: int

        :return: The transaction id for C{generation}.
        :rtype: str

        :raise InvalidGeneration: Raised when the generation does not exist.
        """
        if generation == 0:
            return ''
        log = self._get_transaction_log(start=generation, end=generation)
        if not log:
            raise InvalidGeneration
        _, _, trans_id = log[0]
        return trans_id

    def get_replica_gen_and_trans_id(self, other_replica_uid):
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
        doc_id = '%s%s' % (SYNC_DOC_ID_PREFIX, other_replica_uid)
        try:
            doc = self._database[doc_id]
        except ResourceNotFound:
            doc = {
                '_id': doc_id,
                GENERATION_KEY: 0,
                REPLICA_UID_KEY: str(other_replica_uid),
                TRANSACTION_ID_KEY: '',
            }
            self._database.save(doc)
        gen, trans_id = doc[GENERATION_KEY], doc[TRANSACTION_ID_KEY]
        return gen, trans_id

    def get_doc_conflicts(self, doc_id, couch_rev=None):
        """
        Get the conflicted versions of a document.

        If the C{couch_rev} parameter is not None, conflicts for a specific
        document's couch revision are returned.

        :param couch_rev: The couch document revision.
        :type couch_rev: str

        :return: A list of conflicted versions of the document.
        :rtype: list
        """
        # request conflicts attachment from server
        params = {}
        conflicts = []
        if couch_rev is not None:
            params['rev'] = couch_rev  # restric document's couch revision
        else:
            # TODO: move into resource logic!
            first_entry = self.get_doc(doc_id, check_for_conflicts=True)
            conflicts.append(first_entry)

        try:
            response = self.json_from_resource([doc_id, 'u1db_conflicts'],
                                               **params)
            return conflicts + self._build_conflicts(
                doc_id, json.loads(response.read()))
        except ResourceNotFound:
            return []

    def set_replica_gen_and_trans_id(
            self, other_replica_uid, other_generation, other_transaction_id):
        """
        Set the last-known generation and transaction id for the other
        database replica.

        We have just performed some synchronization, and we want to track what
        generation the other replica was at. See also
        get_replica_gen_and_trans_id.

        :param other_replica_uid: The U1DB identifier for the other replica.
        :type other_replica_uid: str
        :param other_generation: The generation number for the other replica.
        :type other_generation: int
        :param other_transaction_id: The transaction id associated with the
                                     generation.
        :type other_transaction_id: str
        """
        doc_id = '%s%s' % (SYNC_DOC_ID_PREFIX, other_replica_uid)
        try:
            doc = self._database[doc_id]
        except ResourceNotFound:
            doc = {'_id': doc_id}
        doc[GENERATION_KEY] = other_generation
        doc[TRANSACTION_ID_KEY] = other_transaction_id
        self._database.save(doc)

    def get_transaction_log(self):
        """
        This is only for the test suite, it is not part of the api.

        :return: The complete transaction log.
        :rtype: [(str, str)]
        """
        log = self._get_transaction_log()
        return map(lambda i: (i[1], i[2]), log)

    def _get_gen_docs(
            self, start=0, end=9999999999, descending=None, limit=None):
        params = {}
        if descending:
            params['descending'] = 'true'
            # honor couch way of traversing the view tree in reverse order
            start, end = end, start
        params['startkey'] = _get_gen_doc_id(start)
        params['endkey'] = _get_gen_doc_id(end)
        params['include_docs'] = 'true'
        if limit:
            params['limit'] = limit
        view = self._database.view("_all_docs", **params)
        return view.rows

    def _get_transaction_log(self, start=0, end=9999999999):
        # get current gen and trans_id
        rows = self._get_gen_docs(start=start, end=end)
        log = []
        for row in rows:
            doc = row['doc']
            log.append((
                doc[GENERATION_KEY],
                doc[DOC_ID_KEY],
                doc[TRANSACTION_ID_KEY]))
        return log

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
        changes = []
        cur_generation, last_trans_id = self.get_generation_info()
        relevant_tail = self._get_transaction_log(start=old_generation + 1)
        seen = set()
        for generation, doc_id, trans_id in reversed(relevant_tail):
            if doc_id not in seen:
                changes.append((doc_id, generation, trans_id))
                seen.add(doc_id)
        changes.reverse()
        return (cur_generation, last_trans_id, changes)

    def get_generation_info(self):
        """
        Return the current generation.

        :return: A tuple containing the current generation and transaction id.
        :rtype: (int, str)
        """
        if self.batching and self.batch_generation:
            return self.batch_generation
        rows = self._get_gen_docs(descending=True, limit=1)
        if not rows:
            return 0, ''
        gen_doc = rows.pop()['doc']
        return gen_doc[GENERATION_KEY], gen_doc[TRANSACTION_ID_KEY]

    def json_from_resource(self, doc_path, **kwargs):
        """
        Get a resource from it's path and gets a doc's JSON using provided
        parameters.

        :param doc_path: The path to resource.
        :type doc_path: [str]

        :return: The request's data parsed from JSON to a dict.
        :rtype: dict
        """
        if doc_path is not None:
            resource = self._database.resource(*doc_path)
        else:
            resource = self._database.resource()
        _, _, data = resource.get_json(**kwargs)
        return data

    def _allocate_new_generation(self, doc_id, transaction_id, save=True):
        """
        Allocate a new generation number for a document modification.

        We need to allocate a new generation to this document modification by
        creating a new gen doc. In order to avoid concurrent database updates
        from allocating the same new generation, we will try to create the
        document until we succeed, meaning that no other piece of code holds
        the same generation number as ours.

        The loop below would only be executed more than once if:

          1. there's more than one thread trying to modify the user's database,
             and

          2. the execution of getting the current generation and saving the gen
             doc different threads get interleaved (one of them will succeed
             and the others will fail and try again).

        Number 1 only happens when more than one user device is syncing at the
        same time. Number 2 depends on not-so-frequent coincidence of
        code execution.

        Also, in the race between threads for a generation number there's
        always one thread that wins. so if there are N threads in the race, the
        expected number of repetitions of the loop for each thread would be
        N/2. If N is equal to the number of devices that the user has, the
        number of possible repetitions of the loop should always be low.
        """
        while True:
            try:
                # add the gen document
                gen, _ = self.get_generation_info()
                new_gen = gen + 1
                gen_doc = {
                    '_id': _get_gen_doc_id(new_gen),
                    GENERATION_KEY: new_gen,
                    DOC_ID_KEY: doc_id,
                    TRANSACTION_ID_KEY: transaction_id,
                }
                if save:
                    self._database.save(gen_doc)
                break  # succeeded allocating a new generation, proceed
            except ResourceConflict:
                pass  # try again!
        return gen_doc

    def save_document(self, old_doc, doc, transaction_id):
        """
        Put the document in the Couch backend database.

        Note that C{old_doc} must have been fetched with the parameter
        C{check_for_conflicts} equal to True, so we can properly update the
        new document using the conflict information from the old one.

        :param old_doc: The old document version.
        :type old_doc: ServerDocument
        :param doc: The document to be put.
        :type doc: ServerDocument

        :raise RevisionConflict: Raised when trying to update a document but
                                 couch revisions mismatch.
        """
        attachments = {}  # we save content and conflicts as attachments
        parts = []  # and we put it using couch's multipart PUT
        # save content as attachment
        if doc.is_tombstone() is False:
            content = doc.get_json()
            attachments['u1db_content'] = {
                'follows': True,
                'content_type': 'application/octet-stream',
                'length': len(content),
            }
            parts.append(content)

        # save conflicts as attachment
        if doc.has_conflicts is True:
            conflicts = json.dumps(
                map(lambda cdoc: (cdoc.rev, cdoc.content),
                    doc.get_conflicts()))
            attachments['u1db_conflicts'] = {
                'follows': True,
                'content_type': 'application/octet-stream',
                'length': len(conflicts),
            }
            parts.append(conflicts)

        # build the couch document
        couch_doc = {
            '_id': doc.doc_id,
            'u1db_rev': doc.rev,
            '_attachments': attachments,
        }
        # if we are updating a doc we have to add the couch doc revision
        if old_doc is not None and hasattr(old_doc, 'couch_rev'):
            couch_doc['_rev'] = old_doc.couch_rev
        # prepare the multipart PUT
        if not self.batching:
            buf = StringIO()
            envelope = MultipartWriter(buf)
            # the order in which attachments are described inside the
            # serialization of the couch document must match the order in
            # which they are actually written in the multipart structure.
            # Because of that, we use `sorted_keys=True` in the json
            # serialization (so "u1db_conflicts" comes before
            # "u1db_content" on the couch document attachments
            # description), and also reverse the order of the parts before
            # writing them, so the "conflict" part is written before the
            # "content" part.
            envelope.add(
                'application/json',
                json.dumps(couch_doc, sort_keys=True))
            parts.reverse()
            for part in parts:
                envelope.add('application/octet-stream', part)
            envelope.close()
            # try to save and fail if there's a revision conflict
            try:
                resource = self._new_resource()
                resource.put_json(
                    doc.doc_id, body=str(buf.getvalue()),
                    headers=envelope.headers)
            except ResourceConflict:
                raise RevisionConflict()
            self._allocate_new_generation(doc.doc_id, transaction_id)
        else:
            for name, attachment in attachments.items():
                del attachment['follows']
                del attachment['length']
                index = 0 if name is 'u1db_content' else 1
                attachment['data'] = binascii.b2a_base64(
                    parts[index]).strip()
            couch_doc['_attachments'] = attachments
            gen_doc = self._allocate_new_generation(
                doc.doc_id, transaction_id, save=False)
            self.batch_docs[doc.doc_id] = couch_doc
            self.batch_docs[gen_doc['_id']] = gen_doc
            last_gen, last_trans_id = self.batch_generation
            self.batch_generation = (last_gen + 1, transaction_id)

    def _new_resource(self, *path):
        """
        Return a new resource for accessing a couch database.

        :return: A resource for accessing a couch database.
        :rtype: couchdb.http.Resource
        """
        # Workaround for: https://leap.se/code/issues/5448
        url = couch_urljoin(self._database.resource.url, *path)
        resource = Resource(url, Session(timeout=COUCH_TIMEOUT))
        resource.credentials = self._database.resource.credentials
        resource.headers = self._database.resource.headers.copy()
        return resource
