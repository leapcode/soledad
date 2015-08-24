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


import json
import re
import uuid
import logging
import binascii
import time
import sys
import threading


from StringIO import StringIO
from collections import defaultdict
from urlparse import urljoin
from contextlib import contextmanager


from couchdb.client import Server, Database
from couchdb.http import (
    ResourceConflict,
    ResourceNotFound,
    ServerError,
    Session,
    urljoin as couch_urljoin,
    Resource,
)
from u1db import vectorclock
from u1db.errors import (
    DatabaseDoesNotExist,
    InvalidGeneration,
    RevisionConflict,
    InvalidDocId,
    ConflictedDoc,
    DocumentDoesNotExist,
    DocumentAlreadyDeleted,
    Unauthorized,
)
from u1db.backends import CommonBackend, CommonSyncTarget
from u1db.remote import http_app
from u1db.remote.server_state import ServerState


from leap.soledad.common import ddocs, errors
from leap.soledad.common.document import SoledadDocument


logger = logging.getLogger(__name__)


COUCH_TIMEOUT = 120  # timeout for transfers between Soledad server and Couch


class InvalidURLError(Exception):

    """
    Exception raised when Soledad encounters a malformed URL.
    """


class CouchDocument(SoledadDocument):

    """
    This is the document used for maintaining the Couch backend.

    A CouchDocument can fetch and manipulate conflicts and also holds a
    reference to the couch document revision. This data is used to ensure an
    atomic and consistent update of the database.
    """

    def __init__(self, doc_id=None, rev=None, json='{}', has_conflicts=False,
                 syncable=True):
        """
        Container for handling a document that is stored in couch backend.

        :param doc_id: The unique document identifier.
        :type doc_id: str
        :param rev: The revision identifier of the document.
        :type rev: str
        :param json: The JSON string for this document.
        :type json: str
        :param has_conflicts: Boolean indicating if this document has conflicts
        :type has_conflicts: bool
        :param syncable: Should this document be synced with remote replicas?
        :type syncable: bool
        """
        SoledadDocument.__init__(self, doc_id, rev, json, has_conflicts)
        self._couch_rev = None
        self._conflicts = None
        self._transactions = None

    def _ensure_fetch_conflicts(self, get_conflicts_fun):
        """
        Ensure conflict data has been fetched from the server.

        :param get_conflicts_fun: A function which, given the document id and
                                  the couch revision, return the conflicted
                                  versions of the current document.
        :type get_conflicts_fun: function
        """
        if self._conflicts is None:
            self._conflicts = get_conflicts_fun(self.doc_id,
                                                couch_rev=self.couch_rev)
        self.has_conflicts = len(self._conflicts) > 0

    def get_conflicts(self):
        """
        Get the conflicted versions of the document.

        :return: The conflicted versions of the document.
        :rtype: [CouchDocument]
        """
        return self._conflicts

    def set_conflicts(self, conflicts):
        """
        Set the conflicted versions of the document.

        :param conflicts: The conflicted versions of the document.
        :type conflicts: list
        """
        self._conflicts = conflicts
        self.has_conflicts = len(self._conflicts) > 0

    def add_conflict(self, doc):
        """
        Add a conflict to this document.

        :param doc: The conflicted version to be added.
        :type doc: CouchDocument
        """
        if self._conflicts is None:
            raise Exception("Run self._ensure_fetch_conflicts first!")
        self._conflicts.append(doc)
        self.has_conflicts = len(self._conflicts) > 0

    def delete_conflicts(self, conflict_revs):
        """
        Delete conflicted versions of this document.

        :param conflict_revs: The conflicted revisions to be deleted.
        :type conflict_revs: [str]
        """
        if self._conflicts is None:
            raise Exception("Run self._ensure_fetch_conflicts first!")
        self._conflicts = filter(
            lambda doc: doc.rev not in conflict_revs,
            self._conflicts)
        self.has_conflicts = len(self._conflicts) > 0

    def _get_couch_rev(self):
        return self._couch_rev

    def _set_couch_rev(self, rev):
        self._couch_rev = rev

    couch_rev = property(_get_couch_rev, _set_couch_rev)

    def _get_transactions(self):
        return self._transactions

    def _set_transactions(self, rev):
        self._transactions = rev

    transactions = property(_get_transactions, _set_transactions)


# monkey-patch the u1db http app to use CouchDocument
http_app.Document = CouchDocument


def raise_missing_design_doc_error(exc, ddoc_path):
    """
    Raise an appropriate exception when catching a ResourceNotFound when
    accessing a design document.

    :param exc: The exception cought.
    :type exc: ResourceNotFound
    :param ddoc_path: A list representing the requested path.
    :type ddoc_path: list

    :raise MissingDesignDocError: Raised when tried to access a missing design
                                  document.
    :raise MissingDesignDocListFunctionError: Raised when trying to access a
                                              missing list function on a
                                              design document.
    :raise MissingDesignDocNamedViewError: Raised when trying to access a
                                           missing named view on a design
                                           document.
    :raise MissingDesignDocDeletedError: Raised when trying to access a
                                         deleted design document.
    :raise MissingDesignDocUnknownError: Raised when failed to access a design
                                         document for an yet unknown reason.
    """
    path = "".join(ddoc_path)
    if exc.message[1] == 'missing':
        raise errors.MissingDesignDocError(path)
    elif exc.message[1] == 'missing function' or \
            exc.message[1].startswith('missing lists function'):
        raise errors.MissingDesignDocListFunctionError(path)
    elif exc.message[1] == 'missing_named_view':
        raise errors.MissingDesignDocNamedViewError(path)
    elif exc.message[1] == 'deleted':
        raise errors.MissingDesignDocDeletedError(path)
    # other errors are unknown for now
    raise errors.DesignDocUnknownError("%s: %s" % (path, str(exc.message)))


def raise_server_error(exc, ddoc_path):
    """
    Raise an appropriate exception when catching a ServerError when
    accessing a design document.

    :param exc: The exception cought.
    :type exc: ResourceNotFound
    :param ddoc_path: A list representing the requested path.
    :type ddoc_path: list

    :raise MissingDesignDocListFunctionError: Raised when trying to access a
                                              missing list function on a
                                              design document.
    :raise MissingDesignDocUnknownError: Raised when failed to access a design
                                         document for an yet unknown reason.
    """
    path = "".join(ddoc_path)
    msg = exc.message[1][0]
    if msg == 'unnamed_error':
        raise errors.MissingDesignDocListFunctionError(path)
    elif msg == 'TypeError':
        if 'point is undefined' in exc.message[1][1]:
            raise errors.MissingDesignDocListFunctionError
    # other errors are unknown for now
    raise errors.DesignDocUnknownError(path)


class MultipartWriter(object):

    """
    A multipart writer adapted from python-couchdb's one so we can PUT
    documents using couch's multipart PUT.

    This stripped down version does not allow for nested structures, and
    contains only the essential things we need to PUT SoledadDocuments to the
    couch backend.
    """

    CRLF = '\r\n'

    def __init__(self, fileobj, headers=None, boundary=None):
        """
        Initialize the multipart writer.
        """
        self.fileobj = fileobj
        if boundary is None:
            boundary = self._make_boundary()
        self._boundary = boundary
        self._build_headers('related', headers)

    def add(self, mimetype, content, headers={}):
        """
        Add a part to the multipart stream.
        """
        self.fileobj.write('--')
        self.fileobj.write(self._boundary)
        self.fileobj.write(self.CRLF)
        headers['Content-Type'] = mimetype
        self._write_headers(headers)
        if content:
            # XXX: throw an exception if a boundary appears in the content??
            self.fileobj.write(content)
            self.fileobj.write(self.CRLF)

    def close(self):
        """
        Close the multipart stream.
        """
        self.fileobj.write('--')
        self.fileobj.write(self._boundary)
        # be careful not to have anything after '--', otherwise old couch
        # versions (including bigcouch) will fail.
        self.fileobj.write('--')

    def _make_boundary(self):
        """
        Create a boundary to discern multi parts.
        """
        try:
            from uuid import uuid4
            return '==' + uuid4().hex + '=='
        except ImportError:
            from random import randrange
            token = randrange(sys.maxint)
            format = '%%0%dd' % len(repr(sys.maxint - 1))
            return '===============' + (format % token) + '=='

    def _write_headers(self, headers):
        """
        Write a part header in the buffer stream.
        """
        if headers:
            for name in sorted(headers.keys()):
                value = headers[name]
                self.fileobj.write(name)
                self.fileobj.write(': ')
                self.fileobj.write(value)
                self.fileobj.write(self.CRLF)
        self.fileobj.write(self.CRLF)

    def _build_headers(self, subtype, headers):
        """
        Build the main headers of the multipart stream.

        This is here so we can send headers separete from content using
        python-couchdb API.
        """
        self.headers = {}
        self.headers['Content-Type'] = 'multipart/%s; boundary="%s"' % \
                                       (subtype, self._boundary)
        if headers:
            for name in sorted(headers.keys()):
                value = headers[name]
                self.headers[name] = value


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
    server = Server(url=url, session=session)
    yield server


class CouchDatabase(CommonBackend):

    """
    A U1DB implementation that uses CouchDB as its persistence layer.
    """

    # We spawn threads to parallelize the CouchDatabase.get_docs() method
    MAX_GET_DOCS_THREADS = 20

    update_handler_lock = defaultdict(threading.Lock)
    sync_info_lock = defaultdict(threading.Lock)

    class _GetDocThread(threading.Thread):

        """
        A thread that gets a document from a database.

        TODO: switch this for a twisted deferred to thread. This depends on
        replacing python-couchdb for paisley in this module.
        """

        def __init__(self, db, doc_id, check_for_conflicts,
                     release_fun):
            """
            :param db: The database from where to get the document.
            :type db: CouchDatabase
            :param doc_id: The doc_id of the document to be retrieved.
            :type doc_id: str
            :param check_for_conflicts: Whether the get_doc() method should
                                        check for existing conflicts.
            :type check_for_conflicts: bool
            :param release_fun: A function that releases a semaphore, to be
                                called after the document is fetched.
            :type release_fun: function
            """
            threading.Thread.__init__(self)
            self._db = db
            self._doc_id = doc_id
            self._check_for_conflicts = check_for_conflicts
            self._release_fun = release_fun
            self._doc = None

        def run(self):
            """
            Fetch the document, store it as a property, and call the release
            function.
            """
            self._doc = self._db._get_doc(
                self._doc_id, self._check_for_conflicts)
            self._release_fun()

    @classmethod
    def open_database(cls, url, create, replica_uid=None, ensure_ddocs=False):
        """
        Open a U1DB database using CouchDB as backend.

        :param url: the url of the database replica
        :type url: str
        :param create: should the replica be created if it does not exist?
        :type create: bool
        :param replica_uid: an optional unique replica identifier
        :type replica_uid: str
        :param ensure_ddocs: Ensure that the design docs exist on server.
        :type ensure_ddocs: bool

        :return: the database instance
        :rtype: CouchDatabase
        """
        # get database from url
        m = re.match('(^https?://[^/]+)/(.+)$', url)
        if not m:
            raise InvalidURLError
        url = m.group(1)
        dbname = m.group(2)
        with couch_server(url) as server:
            try:
                server[dbname]
            except ResourceNotFound:
                if not create:
                    raise DatabaseDoesNotExist()
                server.create(dbname)
        return cls(
            url, dbname, replica_uid=replica_uid, ensure_ddocs=ensure_ddocs)

    def __init__(self, url, dbname, replica_uid=None, ensure_ddocs=True):
        """
        Create a new Couch data container.

        :param url: the url of the couch database
        :type url: str
        :param dbname: the database name
        :type dbname: str
        :param replica_uid: an optional unique replica identifier
        :type replica_uid: str
        :param ensure_ddocs: Ensure that the design docs exist on server.
        :type ensure_ddocs: bool
        """
        # save params
        self._url = url
        self._session = Session(timeout=COUCH_TIMEOUT)
        self._factory = CouchDocument
        self._real_replica_uid = None
        # configure couch
        self._dbname = dbname
        self._database = Database(
            urljoin(self._url, self._dbname),
            self._session)
        try:
            self._database.info()
        except ResourceNotFound:
            raise DatabaseDoesNotExist()
        if replica_uid is not None:
            self._set_replica_uid(replica_uid)
        if ensure_ddocs:
            self.ensure_ddocs_on_db()
        # initialize a thread pool for parallelizing get_docs()
        self._sem_pool = threading.BoundedSemaphore(
            value=self.MAX_GET_DOCS_THREADS)

    def ensure_ddocs_on_db(self):
        """
        Ensure that the design documents used by the backend exist on the
        couch database.
        """
        # we check for existence of one of the files, and put all of them if
        # that one does not exist
        try:
            self._database['_design/docs']
            return
        except ResourceNotFound:
            for ddoc_name in ['docs', 'syncs', 'transactions']:
                ddoc = json.loads(
                    binascii.a2b_base64(
                        getattr(ddocs, ddoc_name)))
                self._database.save(ddoc)

    def get_sync_target(self):
        """
        Return a SyncTarget object, for another u1db to synchronize with.

        :return: The sync target.
        :rtype: CouchSyncTarget
        """
        return CouchSyncTarget(self)

    def delete_database(self):
        """
        Delete a U1DB CouchDB database.
        """
        with couch_server(self._url) as server:
            del(server[self._dbname])

    def close(self):
        """
        Release any resources associated with this database.

        :return: True if db was succesfully closed.
        :rtype: bool
        """
        self._url = None
        self._full_commit = None
        self._session = None
        self._database = None
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
        try:
            # set on existent config document
            doc = self._database['u1db_config']
            doc['replica_uid'] = replica_uid
        except ResourceNotFound:
            # or create the config document
            doc = {
                '_id': 'u1db_config',
                'replica_uid': replica_uid,
            }
        self._database.save(doc)
        self._real_replica_uid = replica_uid

    def _get_replica_uid(self):
        """
        Get the replica uid.

        :return: The replica uid.
        :rtype: str
        """
        if self._real_replica_uid is not None:
            return self._real_replica_uid
        try:
            # grab replica_uid from server
            doc = self._database['u1db_config']
            self._real_replica_uid = doc['replica_uid']
            return self._real_replica_uid
        except ResourceNotFound:
            # create a unique replica_uid
            self._real_replica_uid = uuid.uuid4().hex
            self._set_replica_uid(self._real_replica_uid)
            return self._real_replica_uid

    _replica_uid = property(_get_replica_uid, _set_replica_uid)

    replica_uid = property(_get_replica_uid)

    def _get_generation(self):
        """
        Return the current generation.

        :return: The current generation.
        :rtype: int

        :raise MissingDesignDocError: Raised when tried to access a missing
                                      design document.
        :raise MissingDesignDocListFunctionError: Raised when trying to access
                                                  a missing list function on a
                                                  design document.
        :raise MissingDesignDocNamedViewError: Raised when trying to access a
                                               missing named view on a design
                                               document.
        :raise MissingDesignDocDeletedError: Raised when trying to access a
                                             deleted design document.
        :raise MissingDesignDocUnknownError: Raised when failed to access a
                                             design document for an yet
                                             unknown reason.
        """
        # query a couch list function
        ddoc_path = ['_design', 'transactions', '_list', 'generation', 'log']
        res = self._database.resource(*ddoc_path)
        try:
            response = res.get_json()
            return response[2]['generation']
        except ResourceNotFound as e:
            raise_missing_design_doc_error(e, ddoc_path)
        except ServerError as e:
            raise_server_error(e, ddoc_path)

    def _get_generation_info(self):
        """
        Return the current generation.

        :return: A tuple containing the current generation and transaction id.
        :rtype: (int, str)

        :raise MissingDesignDocError: Raised when tried to access a missing
                                      design document.
        :raise MissingDesignDocListFunctionError: Raised when trying to access
                                                  a missing list function on a
                                                  design document.
        :raise MissingDesignDocNamedViewError: Raised when trying to access a
                                               missing named view on a design
                                               document.
        :raise MissingDesignDocDeletedError: Raised when trying to access a
                                             deleted design document.
        :raise MissingDesignDocUnknownError: Raised when failed to access a
                                             design document for an yet
                                             unknown reason.
        """
        # query a couch list function
        ddoc_path = ['_design', 'transactions', '_list', 'generation', 'log']
        res = self._database.resource(*ddoc_path)
        try:
            response = res.get_json()
            return (response[2]['generation'], response[2]['transaction_id'])
        except ResourceNotFound as e:
            raise_missing_design_doc_error(e, ddoc_path)
        except ServerError as e:
            raise_server_error(e, ddoc_path)

    def _get_trans_id_for_gen(self, generation):
        """
        Get the transaction id corresponding to a particular generation.

        :param generation: The generation for which to get the transaction id.
        :type generation: int

        :return: The transaction id for C{generation}.
        :rtype: str

        :raise InvalidGeneration: Raised when the generation does not exist.
        :raise MissingDesignDocError: Raised when tried to access a missing
                                      design document.
        :raise MissingDesignDocListFunctionError: Raised when trying to access
                                                  a missing list function on a
                                                  design document.
        :raise MissingDesignDocNamedViewError: Raised when trying to access a
                                               missing named view on a design
                                               document.
        :raise MissingDesignDocDeletedError: Raised when trying to access a
                                             deleted design document.
        :raise MissingDesignDocUnknownError: Raised when failed to access a
                                             design document for an yet
                                             unknown reason.
        """
        if generation == 0:
            return ''
        # query a couch list function
        ddoc_path = [
            '_design', 'transactions', '_list', 'trans_id_for_gen', 'log'
        ]
        res = self._database.resource(*ddoc_path)
        try:
            response = res.get_json(gen=generation)
            if response[2] == {}:
                raise InvalidGeneration
            return response[2]['transaction_id']
        except ResourceNotFound as e:
            raise_missing_design_doc_error(e, ddoc_path)
        except ServerError as e:
            raise_server_error(e, ddoc_path)

    def _get_transaction_log(self):
        """
        This is only for the test suite, it is not part of the api.

        :return: The complete transaction log.
        :rtype: [(str, str)]

        :raise MissingDesignDocError: Raised when tried to access a missing
                                      design document.
        :raise MissingDesignDocListFunctionError: Raised when trying to access
                                                  a missing list function on a
                                                  design document.
        :raise MissingDesignDocNamedViewError: Raised when trying to access a
                                               missing named view on a design
                                               document.
        :raise MissingDesignDocDeletedError: Raised when trying to access a
                                             deleted design document.
        :raise MissingDesignDocUnknownError: Raised when failed to access a
                                             design document for an yet
                                             unknown reason.
        """
        # query a couch view
        ddoc_path = ['_design', 'transactions', '_view', 'log']
        res = self._database.resource(*ddoc_path)
        try:
            response = res.get_json()
            return map(
                lambda row: (row['id'], row['value']),
                response[2]['rows'])
        except ResourceNotFound as e:
            raise_missing_design_doc_error(e, ddoc_path)

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
        :rtype: CouchDocument
        """
        # get document with all attachments (u1db content and eventual
        # conflicts)
        try:
            result = \
                self._database.resource(doc_id).get_json(
                    attachments=True)[2]
        except ResourceNotFound:
            return None
        # restrict to u1db documents
        if 'u1db_rev' not in result:
            return None
        doc = self._factory(doc_id, result['u1db_rev'])
        # set contents or make tombstone
        if '_attachments' not in result \
                or 'u1db_content' not in result['_attachments']:
            doc.make_tombstone()
        else:
            doc.content = json.loads(
                binascii.a2b_base64(
                    result['_attachments']['u1db_content']['data']))
        # determine if there are conflicts
        if check_for_conflicts \
                and '_attachments' in result \
                and 'u1db_conflicts' in result['_attachments']:
            doc.has_conflicts = True
            doc.set_conflicts(
                self._build_conflicts(
                    doc.doc_id,
                    json.loads(binascii.a2b_base64(
                        result['_attachments']['u1db_conflicts']['data']))))
        # store couch revision
        doc.couch_rev = result['_rev']
        # store transactions
        doc.transactions = result['u1db_transactions']
        return doc

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
        :rtype: CouchDocument.
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

        :return: (generation, [CouchDocument])
            The current generation of the database, followed by a list of all
            the documents in the database.
        :rtype: (int, [CouchDocument])
        """

        generation = self._get_generation()
        results = []
        for row in self._database.view('_all_docs'):
            doc = self.get_doc(row.id, include_deleted=include_deleted)
            if doc is not None:
                results.append(doc)
        return (generation, results)

    def _put_doc(self, old_doc, doc):
        """
        Put the document in the Couch backend database.

        Note that C{old_doc} must have been fetched with the parameter
        C{check_for_conflicts} equal to True, so we can properly update the
        new document using the conflict information from the old one.

        :param old_doc: The old document version.
        :type old_doc: CouchDocument
        :param doc: The document to be put.
        :type doc: CouchDocument

        :raise RevisionConflict: Raised when trying to update a document but
                                 couch revisions mismatch.
        :raise MissingDesignDocError: Raised when tried to access a missing
                                      design document.
        :raise MissingDesignDocListFunctionError: Raised when trying to access
                                                  a missing list function on a
                                                  design document.
        :raise MissingDesignDocNamedViewError: Raised when trying to access a
                                               missing named view on a design
                                               document.
        :raise MissingDesignDocDeletedError: Raised when trying to access a
                                             deleted design document.
        :raise MissingDesignDocUnknownError: Raised when failed to access a
                                             design document for an yet
                                             unknown reason.
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
        # store old transactions, if any
        transactions = old_doc.transactions[:] if old_doc is not None else []
        # create a new transaction id and timestamp it so the transaction log
        # is consistent when querying the database.
        transactions.append(
            # here we store milliseconds to keep consistent with javascript
            # Date.prototype.getTime() which was used before inside a couchdb
            # update handler.
            (int(time.time() * 1000),
             self._allocate_transaction_id()))
        # build the couch document
        couch_doc = {
            '_id': doc.doc_id,
            'u1db_rev': doc.rev,
            'u1db_transactions': transactions,
            '_attachments': attachments,
        }
        # if we are updating a doc we have to add the couch doc revision
        if old_doc is not None:
            couch_doc['_rev'] = old_doc.couch_rev
        # prepare the multipart PUT
        buf = StringIO()
        envelope = MultipartWriter(buf)
        envelope.add('application/json', json.dumps(couch_doc))
        for part in parts:
            envelope.add('application/octet-stream', part)
        envelope.close()
        # try to save and fail if there's a revision conflict
        try:
            resource = self._new_resource()
            resource.put_json(
                doc.doc_id, body=buf.getvalue(), headers=envelope.headers)
        except ResourceConflict:
            raise RevisionConflict()

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

        :raise MissingDesignDocError: Raised when tried to access a missing
                                      design document.
        :raise MissingDesignDocListFunctionError: Raised when trying to access
                                                  a missing list function on a
                                                  design document.
        :raise MissingDesignDocNamedViewError: Raised when trying to access a
                                               missing named view on a design
                                               document.
        :raise MissingDesignDocDeletedError: Raised when trying to access a
                                             deleted design document.
        :raise MissingDesignDocUnknownError: Raised when failed to access a
                                             design document for an yet
                                             unknown reason.
        """
        # query a couch list function
        ddoc_path = [
            '_design', 'transactions', '_list', 'whats_changed', 'log'
        ]
        res = self._database.resource(*ddoc_path)
        try:
            response = res.get_json(old_gen=old_generation)
            results = map(
                lambda row:
                    (row['generation'], row['doc_id'], row['transaction_id']),
                response[2]['transactions'])
            results.reverse()
            cur_gen = old_generation
            seen = set()
            changes = []
            newest_trans_id = ''
            for generation, doc_id, trans_id in results:
                if doc_id not in seen:
                    changes.append((doc_id, generation, trans_id))
                    seen.add(doc_id)
            if changes:
                cur_gen = changes[0][1]  # max generation
                newest_trans_id = changes[0][2]
                changes.reverse()
            else:
                cur_gen, newest_trans_id = self._get_generation_info()

            return cur_gen, newest_trans_id, changes
        except ResourceNotFound as e:
            raise_missing_design_doc_error(e, ddoc_path)
        except ServerError as e:
            raise_server_error(e, ddoc_path)

    def delete_doc(self, doc):
        """
        Mark a document as deleted.

        Will abort if the current revision doesn't match doc.rev.
        This will also set doc.content to None.

        :param doc: The document to mark as deleted.
        :type doc: CouchDocument.

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
            doc = self._factory(doc_id, doc_rev)
            if content is None:
                doc.make_tombstone()
            else:
                doc.content = content
            conflicts.append(doc)
        return conflicts

    def _get_conflicts(self, doc_id, couch_rev=None):
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
        if couch_rev is not None:
            params['rev'] = couch_rev  # restric document's couch revision
        resource = self._database.resource(doc_id, 'u1db_conflicts')
        try:
            response = resource.get_json(**params)
            return self._build_conflicts(
                doc_id, json.loads(response[2].read()))
        except ResourceNotFound:
            return []

    def get_doc_conflicts(self, doc_id):
        """
        Get the list of conflicts for the given document.

        The order of the conflicts is such that the first entry is the value
        that would be returned by "get_doc".

        :return: A list of the document entries that are conflicted.
        :rtype: [CouchDocument]
        """
        conflict_docs = self._get_conflicts(doc_id)
        if len(conflict_docs) == 0:
            return []
        this_doc = self._get_doc(doc_id, check_for_conflicts=True)
        return [this_doc] + conflict_docs

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
        # query a couch view
        result = self._database.view('syncs/log')
        if len(result[other_replica_uid].rows) == 0:
            return (0, '')
        return (
            result[other_replica_uid].rows[0]['value']['known_generation'],
            result[other_replica_uid].rows[0]['value']['known_transaction_id']
        )

    def _set_replica_gen_and_trans_id(self, other_replica_uid,
                                      other_generation, other_transaction_id,
                                      number_of_docs=None, doc_idx=None,
                                      sync_id=None):
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
        :param number_of_docs: The total amount of documents sent on this sync
                               session.
        :type number_of_docs: int
        :param doc_idx: The index of the current document being sent.
        :type doc_idx: int
        :param sync_id: The id of the current sync session.
        :type sync_id: str
        """
        self._do_set_replica_gen_and_trans_id(
            other_replica_uid, other_generation, other_transaction_id,
            number_of_docs=number_of_docs, doc_idx=doc_idx, sync_id=sync_id)

    def _do_set_replica_gen_and_trans_id(
            self, other_replica_uid, other_generation, other_transaction_id,
            number_of_docs=None, doc_idx=None, sync_id=None):
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
        :param number_of_docs: The total amount of documents sent on this sync
                               session.
        :type number_of_docs: int
        :param doc_idx: The index of the current document being sent.
        :type doc_idx: int
        :param sync_id: The id of the current sync session.
        :type sync_id: str

        :raise MissingDesignDocError: Raised when tried to access a missing
                                      design document.
        :raise MissingDesignDocListFunctionError: Raised when trying to access
                                                  a missing list function on a
                                                  design document.
        :raise MissingDesignDocNamedViewError: Raised when trying to access a
                                               missing named view on a design
                                               document.
        :raise MissingDesignDocDeletedError: Raised when trying to access a
                                             deleted design document.
        :raise MissingDesignDocUnknownError: Raised when failed to access a
                                             design document for an yet
                                             unknown reason.
        """
        # query a couch update function
        ddoc_path = ['_design', 'syncs', '_update', 'put', 'u1db_sync_log']
        res = self._database.resource(*ddoc_path)
        try:
            with CouchDatabase.update_handler_lock[self._get_replica_uid()]:
                body = {
                    'other_replica_uid': other_replica_uid,
                    'other_generation': other_generation,
                    'other_transaction_id': other_transaction_id,
                }
                if number_of_docs is not None:
                    body['number_of_docs'] = number_of_docs
                if doc_idx is not None:
                    body['doc_idx'] = doc_idx
                if sync_id is not None:
                    body['sync_id'] = sync_id
                res.put_json(
                    body=body,
                    headers={'content-type': 'application/json'})
        except ResourceNotFound as e:
            raise_missing_design_doc_error(e, ddoc_path)

    def _add_conflict(self, doc, my_doc_rev, my_content):
        """
        Add a conflict to the document.

        Note that this method does not actually update the backend; rather, it
        updates the CouchDocument object which will provide the conflict data
        when the atomic document update is made.

        :param doc: The document to have conflicts added to.
        :type doc: CouchDocument
        :param my_doc_rev: The revision of the conflicted document.
        :type my_doc_rev: str
        :param my_content: The content of the conflicted document as a JSON
                           serialized string.
        :type my_content: str
        """
        doc._ensure_fetch_conflicts(self._get_conflicts)
        doc.add_conflict(
            self._factory(doc_id=doc.doc_id, rev=my_doc_rev,
                          json=my_content))

    def _delete_conflicts(self, doc, conflict_revs):
        """
        Delete the conflicted revisions from the list of conflicts of C{doc}.

        Note that this method does not actually update the backend; rather, it
        updates the CouchDocument object which will provide the conflict data
        when the atomic document update is made.

        :param doc: The document to have conflicts deleted.
        :type doc: CouchDocument
        :param conflict_revs: A list of the revisions to be deleted.
        :param conflict_revs: [str]
        """
        doc._ensure_fetch_conflicts(self._get_conflicts)
        doc.delete_conflicts(conflict_revs)

    def _prune_conflicts(self, doc, doc_vcr):
        """
        Prune conflicts that are older then the current document's revision, or
        whose content match to the current document's content.

        :param doc: The document to have conflicts pruned.
        :type doc: CouchDocument
        :param doc_vcr: A vector clock representing the current document's
                        revision.
        :type doc_vcr: u1db.vectorclock.VectorClock
        """
        if doc.has_conflicts is True:
            autoresolved = False
            c_revs_to_prune = []
            for c_doc in doc.get_conflicts():
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
            self._delete_conflicts(doc, c_revs_to_prune)

    def _force_doc_sync_conflict(self, doc):
        """
        Add a conflict and force a document put.

        :param doc: The document to be put.
        :type doc: CouchDocument
        """
        my_doc = self._get_doc(doc.doc_id, check_for_conflicts=True)
        self._prune_conflicts(doc, vectorclock.VectorClockRev(doc.rev))
        self._add_conflict(doc, my_doc.rev, my_doc.get_json())
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
        :type doc: CouchDocument
        :param conflicted_doc_revs: A list of revisions that the new content
                                    supersedes.
        :type conflicted_doc_revs: [str]

        :raise MissingDesignDocError: Raised when tried to access a missing
                                      design document.
        :raise MissingDesignDocListFunctionError: Raised when trying to access
                                                  a missing list function on a
                                                  design document.
        :raise MissingDesignDocNamedViewError: Raised when trying to access a
                                               missing named view on a design
                                               document.
        :raise MissingDesignDocDeletedError: Raised when trying to access a
                                             deleted design document.
        :raise MissingDesignDocUnknownError: Raised when failed to access a
                                             design document for an yet
                                             unknown reason.
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
            self._delete_conflicts(doc, superseded_revs)
            self._put_doc(cur_doc, doc)
        else:
            # the newer doc version does not supersede the one in the
            # database, so we will add a conflict to the database and copy
            # those over to the document the user has in her hands.
            self._add_conflict(cur_doc, new_rev, doc.get_json())
            self._delete_conflicts(cur_doc, superseded_revs)
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
        :type doc: CouchDocument
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
        cur_doc = self._get_doc(doc.doc_id, check_for_conflicts=True)
        # at this point, `doc` has arrived from the other syncing party, and
        # we will decide what to do with it.
        # First, we prepare the arriving doc to update couch database.
        old_doc = doc
        doc = self._factory(doc.doc_id, doc.rev, doc.get_json())
        if cur_doc is not None:
            doc.couch_rev = cur_doc.couch_rev
        # fetch conflicts because we will eventually manipulate them
        doc._ensure_fetch_conflicts(self._get_conflicts)
        # from now on, it works just like u1db sqlite backend
        doc_vcr = vectorclock.VectorClockRev(doc.rev)
        if cur_doc is None:
            cur_vcr = vectorclock.VectorClockRev(None)
        else:
            cur_vcr = vectorclock.VectorClockRev(cur_doc.rev)
        self._validate_source(replica_uid, replica_gen, replica_trans_id)
        if doc_vcr.is_newer(cur_vcr):
            rev = doc.rev
            self._prune_conflicts(doc, doc_vcr)
            if doc.rev != rev:
                # conflicts have been autoresolved
                state = 'superseded'
            else:
                state = 'inserted'
            self._put_doc(cur_doc, doc)
        elif doc.rev == cur_doc.rev:
            # magical convergence
            state = 'converged'
        elif cur_vcr.is_newer(doc_vcr):
            # Don't add this to seen_ids, because we have something newer,
            # so we should send it back, and we should not generate a
            # conflict
            state = 'superseded'
        elif cur_doc.same_content_as(doc):
            # the documents have been edited to the same thing at both ends
            doc_vcr.maximize(cur_vcr)
            doc_vcr.increment(self._replica_uid)
            doc.rev = doc_vcr.as_str()
            self._put_doc(cur_doc, doc)
            state = 'superseded'
        else:
            state = 'conflicted'
            if save_conflict:
                self._force_doc_sync_conflict(doc)
        if replica_uid is not None and replica_gen is not None:
            self._set_replica_gen_and_trans_id(
                replica_uid, replica_gen, replica_trans_id,
                number_of_docs=number_of_docs, doc_idx=doc_idx,
                sync_id=sync_id)
        # update info
        old_doc.rev = doc.rev
        if doc.is_tombstone():
            old_doc.is_tombstone()
        else:
            old_doc.content = doc.content
        old_doc.has_conflicts = doc.has_conflicts
        return state, self._get_generation()

    def get_docs(self, doc_ids, check_for_conflicts=True,
                 include_deleted=False):
        """
        Get the JSON content for many documents.

        :param doc_ids: A list of document identifiers.
        :type doc_ids: list
        :param check_for_conflicts: If set to False, then the conflict check
                                    will be skipped, and 'None' will be
                                    returned instead of True/False.
        :type check_for_conflictsa: bool
        :param include_deleted: If set to True, deleted documents will be
                                returned with empty content. Otherwise deleted
                                documents will not be included in the results.
        :return: iterable giving the Document object for each document id
                 in matching doc_ids order.
        :rtype: iterable
        """
        # Workaround for:
        #
        #   http://bugs.python.org/issue7980
        #   https://leap.se/code/issues/5449
        #
        # python-couchdb uses time.strptime, which is not thread safe. In
        # order to avoid the problem described on the issues above, we preload
        # strptime here by evaluating the conversion of an arbitrary date.
        # This will not be needed when/if we switch from python-couchdb to
        # paisley.
        time.strptime('Mar 8 1917', '%b %d %Y')
        # spawn threads to retrieve docs
        threads = []
        for doc_id in doc_ids:
            self._sem_pool.acquire()
            t = self._GetDocThread(self, doc_id, check_for_conflicts,
                                   self._sem_pool.release)
            t.start()
            threads.append(t)
        # join threads and yield docs
        for t in threads:
            t.join()
            if t._doc.is_tombstone() and not include_deleted:
                continue
            yield t._doc

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


class CouchSyncTarget(CommonSyncTarget):

    """
    Functionality for using a CouchDatabase as a synchronization target.
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


class CouchServerState(ServerState):

    """
    Inteface of the WSGI server with the CouchDB backend.
    """

    def __init__(self, couch_url):
        """
        Initialize the couch server state.

        :param couch_url: The URL for the couch database.
        :type couch_url: str
        """
        self._couch_url = couch_url

    def open_database(self, dbname):
        """
        Open a couch database.

        :param dbname: The name of the database to open.
        :type dbname: str

        :return: The CouchDatabase object.
        :rtype: CouchDatabase
        """
        return CouchDatabase(
            self._couch_url,
            dbname,
            ensure_ddocs=False)

    def ensure_database(self, dbname):
        """
        Ensure couch database exists.

        Usually, this method is used by the server to ensure the existence of
        a database. In our setup, the Soledad user that accesses the underlying
        couch server should never have permission to create (or delete)
        databases. But, in case it ever does, by raising an exception here we
        have one more guarantee that no modified client will be able to
        enforce creation of a database when syncing.

        :param dbname: The name of the database to ensure.
        :type dbname: str

        :raise Unauthorized: Always, because Soledad server is not allowed to
                             create databases.
        """
        raise Unauthorized()

    def delete_database(self, dbname):
        """
        Delete couch database.

        :param dbname: The name of the database to delete.
        :type dbname: str

        :raise Unauthorized: Always, because Soledad server is not allowed to
                             delete databases.
        """
        raise Unauthorized()

    def _set_couch_url(self, url):
        """
        Set the couchdb URL

        :param url: CouchDB URL
        :type url: str
        """
        self._couch_url = url

    def _get_couch_url(self):
        """
        Return CouchDB URL

        :rtype: str
        """
        return self._couch_url

    couch_url = property(_get_couch_url, _set_couch_url, doc='CouchDB URL')
