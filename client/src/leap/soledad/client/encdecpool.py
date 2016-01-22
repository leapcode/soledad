# -*- coding: utf-8 -*-
# encdecpool.py
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
A pool of encryption/decryption concurrent and parallel workers for using
during synchronization.
"""


import multiprocessing
import Queue
import json
import logging

from twisted.internet import reactor
from twisted.internet import threads
from twisted.internet import defer
from twisted.python import log

from leap.soledad.common.document import SoledadDocument
from leap.soledad.common import soledad_assert

from leap.soledad.client.crypto import encrypt_docstr
from leap.soledad.client.crypto import decrypt_doc_dict


logger = logging.getLogger(__name__)


#
# Encrypt/decrypt pools of workers
#

class SyncEncryptDecryptPool(object):
    """
    Base class for encrypter/decrypter pools.
    """

    # TODO implement throttling to reduce cpu usage??
    WORKERS = multiprocessing.cpu_count()

    def __init__(self, crypto, sync_db):
        """
        Initialize the pool of encryption-workers.

        :param crypto: A SoledadCryto instance to perform the encryption.
        :type crypto: leap.soledad.crypto.SoledadCrypto

        :param sync_db: A database connection handle
        :type sync_db: pysqlcipher.dbapi2.Connection
        """
        self._crypto = crypto
        self._sync_db = sync_db
        self._pool = None
        self._delayed_call = None
        self._started = False

    def start(self):
        if self.running:
            return
        self._create_pool()
        self._started = True

    def stop(self):
        if not self.running:
            return
        self._started = False
        self._destroy_pool()
        # maybe cancel the next delayed call
        if self._delayed_call \
                and not self._delayed_call.called:
            self._delayed_call.cancel()

    @property
    def running(self):
        return self._started

    def _create_pool(self):
        self._pool = multiprocessing.Pool(self.WORKERS)

    def _destroy_pool(self):
        """
        Cleanly close the pool of workers.
        """
        logger.debug("Closing %s" % (self.__class__.__name__,))
        self._pool.close()
        try:
            self._pool.join()
        except Exception:
            pass

    def terminate(self):
        """
        Terminate the pool of workers.
        """
        logger.debug("Terminating %s" % (self.__class__.__name__,))
        self._pool.terminate()

    def _runOperation(self, query, *args):
        """
        Run an operation on the sync db.

        :param query: The query to be executed.
        :type query: str
        :param args: A list of query arguments.
        :type args: list

        :return: A deferred that will fire when the operation in the database
                 has finished.
        :rtype: twisted.internet.defer.Deferred
        """
        return self._sync_db.runOperation(query, *args)

    def _runQuery(self, query, *args):
        """
        Run a query on the sync db.

        :param query: The query to be executed.
        :type query: str
        :param args: A list of query arguments.
        :type args: list

        :return: A deferred that will fire with the results of the database
                 query.
        :rtype: twisted.internet.defer.Deferred
        """
        return self._sync_db.runQuery(query, *args)


def encrypt_doc_task(doc_id, doc_rev, content, key, secret):
    """
    Encrypt the content of the given document.

    :param doc_id: The document id.
    :type doc_id: str
    :param doc_rev: The document revision.
    :type doc_rev: str
    :param content: The serialized content of the document.
    :type content: str
    :param key: The encryption key.
    :type key: str
    :param secret: The Soledad storage secret (used for MAC auth).
    :type secret: str

    :return: A tuple containing the doc id, revision and encrypted content.
    :rtype: tuple(str, str, str)
    """
    encrypted_content = encrypt_docstr(
        content, doc_id, doc_rev, key, secret)
    return doc_id, doc_rev, encrypted_content


class SyncEncrypterPool(SyncEncryptDecryptPool):
    """
    Pool of workers that spawn subprocesses to execute the symmetric encryption
    of documents to be synced.
    """
    TABLE_NAME = "docs_tosync"
    FIELD_NAMES = "doc_id PRIMARY KEY, rev, content"

    ENCRYPT_LOOP_PERIOD = 2

    def __init__(self, *args, **kwargs):
        """
        Initialize the sync encrypter pool.
        """
        SyncEncryptDecryptPool.__init__(self, *args, **kwargs)
        self._encr_queue = defer.DeferredQueue()
        # TODO delete already synced files from database

    def start(self):
        """
        Start the encrypter pool.
        """
        SyncEncryptDecryptPool.start(self)
        logger.debug("Starting the encryption loop...")
        reactor.callWhenRunning(self._maybe_encrypt_and_recurse)

    def stop(self):
        """
        Stop the encrypter pool.
        """
        # close the sync queue
        if self._encr_queue:
            q = self._encr_queue
            for d in q.pending:
                d.cancel()
            del q
            self._encr_queue = None

        SyncEncryptDecryptPool.stop(self)

    def enqueue_doc_for_encryption(self, doc):
        """
        Enqueue a document for encryption.

        :param doc: The document to be encrypted.
        :type doc: SoledadDocument
        """
        try:
            self._encr_queue.put(doc)
        except Queue.Full:
            # do not asynchronously encrypt this file if the queue is full
            pass

    @defer.inlineCallbacks
    def _maybe_encrypt_and_recurse(self):
        """
        Process one document from the encryption queue.

        Asynchronously encrypt a document that will then be stored in the sync
        db. Processed documents will be read by the SoledadSyncTarget during
        the sync_exchange.
        """
        try:
            while self.running:
                doc = yield self._encr_queue.get()
                self._encrypt_doc(doc)
        except defer.QueueUnderflow:
            self._delayed_call = reactor.callLater(
                self.ENCRYPT_LOOP_PERIOD,
                self._maybe_encrypt_and_recurse)

    def _encrypt_doc(self, doc):
        """
        Symmetrically encrypt a document.

        :param doc: The document with contents to be encrypted.
        :type doc: SoledadDocument

        :param workers: Whether to defer the decryption to the multiprocess
                        pool of workers. Useful for debugging purposes.
        :type workers: bool
        """
        soledad_assert(self._crypto is not None, "need a crypto object")
        docstr = doc.get_json()
        key = self._crypto.doc_passphrase(doc.doc_id)
        secret = self._crypto.secret
        args = doc.doc_id, doc.rev, docstr, key, secret
        # encrypt asynchronously
        self._pool.apply_async(
            encrypt_doc_task, args,
            callback=self._encrypt_doc_cb)

    def _encrypt_doc_cb(self, result):
        """
        Insert results of encryption routine into the local sync database.

        :param result: A tuple containing the doc id, revision and encrypted
                       content.
        :type result: tuple(str, str, str)
        """
        doc_id, doc_rev, content = result
        return self._insert_encrypted_local_doc(doc_id, doc_rev, content)

    def _insert_encrypted_local_doc(self, doc_id, doc_rev, content):
        """
        Insert the contents of the encrypted doc into the local sync
        database.

        :param doc_id: The document id.
        :type doc_id: str
        :param doc_rev: The document revision.
        :type doc_rev: str
        :param content: The serialized content of the document.
        :type content: str
        """
        query = "INSERT OR REPLACE INTO '%s' VALUES (?, ?, ?)" \
                % (self.TABLE_NAME,)
        return self._runOperation(query, (doc_id, doc_rev, content))

    @defer.inlineCallbacks
    def get_encrypted_doc(self, doc_id, doc_rev):
        """
        Get an encrypted document from the sync db.

        :param doc_id: The id of the document.
        :type doc_id: str
        :param doc_rev: The revision of the document.
        :type doc_rev: str

        :return: A deferred that will fire with the encrypted content of the
                 document or None if the document was not found in the sync
                 db.
        :rtype: twisted.internet.defer.Deferred
        """
        query = "SELECT content FROM %s WHERE doc_id=? and rev=?" \
                % self.TABLE_NAME
        result = yield self._runQuery(query, (doc_id, doc_rev))
        if result:
            logger.debug("Found doc on sync db: %s" % doc_id)
            val = result.pop()
            defer.returnValue(val[0])
        logger.debug("Did not find doc on sync db: %s" % doc_id)
        defer.returnValue(None)

    def delete_encrypted_doc(self, doc_id, doc_rev):
        """
        Delete an encrypted document from the sync db.

        :param doc_id: The id of the document.
        :type doc_id: str
        :param doc_rev: The revision of the document.
        :type doc_rev: str

        :return: A deferred that will fire when the operation in the database
                 has finished.
        :rtype: twisted.internet.defer.Deferred
        """
        query = "DELETE FROM %s WHERE doc_id=? and rev=?" \
                % self.TABLE_NAME
        self._runOperation(query, (doc_id, doc_rev))


def decrypt_doc_task(doc_id, doc_rev, content, gen, trans_id, key, secret,
                     idx):
    """
    Decrypt the content of the given document.

    :param doc_id: The document id.
    :type doc_id: str
    :param doc_rev: The document revision.
    :type doc_rev: str
    :param content: The encrypted content of the document.
    :type content: str
    :param gen: The generation corresponding to the modification of that
                document.
    :type gen: int
    :param trans_id: The transaction id corresponding to the modification of
                     that document.
    :type trans_id: str
    :param key: The encryption key.
    :type key: str
    :param secret: The Soledad storage secret (used for MAC auth).
    :type secret: str
    :param idx: The index of this document in the current sync process.
    :type idx: int

    :return: A tuple containing the doc id, revision and encrypted content.
    :rtype: tuple(str, str, str)
    """
    decrypted_content = decrypt_doc_dict(content, doc_id, doc_rev, key, secret)
    return doc_id, doc_rev, decrypted_content, gen, trans_id, idx


class SyncDecrypterPool(SyncEncryptDecryptPool):
    """
    Pool of workers that spawn subprocesses to execute the symmetric decryption
    of documents that were received.

    The decryption of the received documents is done in two steps:

        1. Encrypted documents are stored in the sync db by the actual soledad
           sync loop.
        2. The soledad sync loop tells us how many documents we should expect
           to process.
        3. We start a decrypt-and-process loop:

            a. Encrypted documents are fetched.
            b. Encrypted documents are decrypted.
            c. The longest possible list of decrypted documents are inserted
               in the soledad db (this depends on which documents have already
               arrived and which documents have already been decrypte, because
               the order of insertion in the local soledad db matters).
            d. Processed documents are deleted from the database.

        4. When we have processed as many documents as we should, the loop
           finishes.
    """
    TABLE_NAME = "docs_received"
    FIELD_NAMES = "doc_id PRIMARY KEY, rev, content, gen, " \
                  "trans_id, encrypted, idx"

    """
    Period of recurrence of the periodic decrypting task, in seconds.
    """
    DECRYPT_LOOP_PERIOD = 0.5

    def __init__(self, *args, **kwargs):
        """
        Initialize the decrypter pool, and setup a dict for putting the
        results of the decrypted docs until they are picked by the insert
        routine that gets them in order.

        :param insert_doc_cb: A callback for inserting received documents from
                              target. If not overriden, this will call u1db
                              insert_doc_from_target in synchronizer, which
                              implements the TAKE OTHER semantics.
        :type insert_doc_cb: function
        :param source_replica_uid: The source replica uid, used to find the
                                   correct callback for inserting documents.
        :type source_replica_uid: str
        """
        self._insert_doc_cb = kwargs.pop("insert_doc_cb")
        self.source_replica_uid = kwargs.pop("source_replica_uid")

        SyncEncryptDecryptPool.__init__(self, *args, **kwargs)

        self._docs_to_process = None
        self._processed_docs = 0
        self._last_inserted_idx = 0
        self._decrypting_docs = []

        # a list that holds the asynchronous decryption results so they can be
        # collected when they are ready
        self._async_results = []

        # initialize db and make sure any database operation happens after
        # db initialization
        self._deferred_init = self._init_db()
        self._wait_init_db('_runOperation', '_runQuery')

    def _wait_init_db(self, *methods):
        """
        Methods that need to wait for db initialization.

        :param methods: methods that need to wait for initialization
        :type methods: tuple(str)
        """
        self._waiting = []
        self._stored = {}

        def _restore(_):
            for method in self._stored:
                setattr(self, method, self._stored[method])
            for d in self._waiting:
                d.callback(None)

        def _makeWrapper(method):
            def wrapper(*args, **kw):
                d = defer.Deferred()
                d.addCallback(lambda _: self._stored[method](*args, **kw))
                self._waiting.append(d)
                return d
            return wrapper

        for method in methods:
            self._stored[method] = getattr(self, method)
            setattr(self, method, _makeWrapper(method))

        self._deferred_init.addCallback(_restore)

    def start(self, docs_to_process):
        """
        Set the number of documents we expect to process.

        This should be called by the during the sync exchange process as soon
        as we know how many documents are arriving from the server.

        :param docs_to_process: The number of documents to process.
        :type docs_to_process: int
        """
        SyncEncryptDecryptPool.start(self)
        self._docs_to_process = docs_to_process
        self._deferred = defer.Deferred()
        reactor.callWhenRunning(self._launch_decrypt_and_recurse)

    def _launch_decrypt_and_recurse(self):
        d = self._decrypt_and_recurse()
        d.addErrback(self._errback)

    def _errback(self, failure):
        log.err(failure)
        self._deferred.errback(failure)
        self._processed_docs = 0
        self._last_inserted_idx = 0

    @property
    def deferred(self):
        """
        Deferred that will be fired when the decryption loop has finished
        processing all the documents.
        """
        return self._deferred

    def insert_encrypted_received_doc(
            self, doc_id, doc_rev, content, gen, trans_id, idx):
        """
        Insert a received message with encrypted content, to be decrypted later
        on.

        :param doc_id: The document ID.
        :type doc_id: str
        :param doc_rev: The document Revision
        :param doc_rev: str
        :param content: The content of the document
        :type content: dict
        :param gen: The document Generation
        :type gen: int
        :param trans_id: Transaction ID
        :type trans_id: str
        :param idx: The index of this document in the current sync process.
        :type idx: int

        :return: A deferred that will fire when the operation in the database
                 has finished.
        :rtype: twisted.internet.defer.Deferred
        """
        docstr = json.dumps(content)
        query = "INSERT OR REPLACE INTO '%s' VALUES (?, ?, ?, ?, ?, ?, ?)" \
                % self.TABLE_NAME
        return self._runOperation(
            query, (doc_id, doc_rev, docstr, gen, trans_id, 1, idx))

    def insert_received_doc(
            self, doc_id, doc_rev, content, gen, trans_id, idx):
        """
        Insert a document that is not symmetrically encrypted.
        We store it in the staging area (the decrypted_docs dictionary) to be
        picked up in order as the preceding documents are decrypted.

        :param doc_id: The document id
        :type doc_id: str
        :param doc_rev: The document revision
        :param doc_rev: str or dict
        :param content: The content of the document
        :type content: dict
        :param gen: The document generation
        :type gen: int
        :param trans_id: The transaction id
        :type trans_id: str
        :param idx: The index of this document in the current sync process.
        :type idx: int

        :return: A deferred that will fire when the operation in the database
                 has finished.
        :rtype: twisted.internet.defer.Deferred
        """
        if not isinstance(content, str):
            content = json.dumps(content)
        query = "INSERT OR REPLACE INTO '%s' VALUES (?, ?, ?, ?, ?, ?, ?)" \
                % self.TABLE_NAME
        return self._runOperation(
            query, (doc_id, doc_rev, content, gen, trans_id, 0, idx))

    def _delete_received_doc(self, doc_id):
        """
        Delete a received doc after it was inserted into the local db.

        :param doc_id: Document ID.
        :type doc_id: str

        :return: A deferred that will fire when the operation in the database
                 has finished.
        :rtype: twisted.internet.defer.Deferred
        """
        query = "DELETE FROM '%s' WHERE doc_id=?" \
                % self.TABLE_NAME
        return self._runOperation(query, (doc_id,))

    def _async_decrypt_doc(self, doc_id, rev, content, gen, trans_id, idx):
        """
        Dispatch an asynchronous document decrypting routine and save the
        result object.

        :param doc_id: The ID for the document with contents to be encrypted.
        :type doc: str
        :param rev: The revision of the document.
        :type rev: str
        :param content: The serialized content of the document.
        :type content: str
        :param gen: The generation corresponding to the modification of that
                    document.
        :type gen: int
        :param trans_id: The transaction id corresponding to the modification
                         of that document.
        :type trans_id: str
        :param idx: The index of this document in the current sync process.
        :type idx: int
        """
        soledad_assert(self._crypto is not None, "need a crypto object")

        content = json.loads(content)
        key = self._crypto.doc_passphrase(doc_id)
        secret = self._crypto.secret
        args = doc_id, rev, content, gen, trans_id, key, secret, idx
        # decrypt asynchronously
        self._async_results.append(
            self._pool.apply_async(
                decrypt_doc_task, args))

    def _decrypt_doc_cb(self, result):
        """
        Store the decryption result in the sync db from where it will later be
        picked by _process_decrypted_docs.

        :param result: A tuple containing the document's id, revision,
                       content, generation, transaction id and sync index.
        :type result: tuple(str, str, str, int, str, int)

        :return: A deferred that will fire after the document has been
                 inserted in the sync db.
        :rtype: twisted.internet.defer.Deferred
        """
        doc_id, rev, content, gen, trans_id, idx = result
        logger.debug("Sync decrypter pool: decrypted doc %s: %s %s %s"
                     % (doc_id, rev, gen, trans_id))
        self._decrypting_docs.remove((doc_id, rev))
        return self.insert_received_doc(
            doc_id, rev, content, gen, trans_id, idx)

    def _get_docs(self, encrypted=None, order_by='idx', order='ASC'):
        """
        Get documents from the received docs table in the sync db.

        :param encrypted: If not None, only return documents with encrypted
                          field equal to given parameter.
        :type encrypted: bool or None
        :param order_by: The name of the field to order results.
        :type order_by: str
        :param order: Whether the order should be ASC or DESC.
        :type order: str

        :return: A deferred that will fire with the results of the database
                 query.
        :rtype: twisted.internet.defer.Deferred
        """
        query = "SELECT doc_id, rev, content, gen, trans_id, encrypted, " \
                "idx FROM %s" % self.TABLE_NAME
        if encrypted is not None:
            query += " WHERE encrypted = %d" % int(encrypted)
        query += " ORDER BY %s %s" % (order_by, order)
        return self._runQuery(query)

    @defer.inlineCallbacks
    def _get_insertable_docs(self):
        """
        Return a list of non-encrypted documents ready to be inserted.

        :return: A deferred that will fire with the list of insertable
                 documents.
        :rtype: twisted.internet.defer.Deferred
        """
        # here, we fetch the list of decrypted documents and compare with the
        # index of the last succesfully processed document.
        decrypted_docs = yield self._get_docs(encrypted=False)
        insertable = []
        last_idx = self._last_inserted_idx
        for doc_id, rev, content, gen, trans_id, encrypted, idx in \
                decrypted_docs:
            if (idx != last_idx + 1):
                break
            insertable.append((doc_id, rev, content, gen, trans_id, idx))
            last_idx += 1
        defer.returnValue(insertable)

    @defer.inlineCallbacks
    def _async_decrypt_received_docs(self):
        """
        Get all the encrypted documents from the sync database and dispatch a
        decrypt worker to decrypt each one of them.

        :return: A deferred that will fire after all documents have been
                 decrypted and inserted back in the sync db.
        :rtype: twisted.internet.defer.Deferred
        """
        docs = yield self._get_docs(encrypted=True)
        for doc_id, rev, content, gen, trans_id, _, idx in docs:
            if (doc_id, rev) not in self._decrypting_docs:
                self._decrypting_docs.append((doc_id, rev))
                self._async_decrypt_doc(
                    doc_id, rev, content, gen, trans_id, idx)

    @defer.inlineCallbacks
    def _process_decrypted_docs(self):
        """
        Fetch as many decrypted documents as can be taken from the expected
        order and insert them in the local replica.

        :return: A deferred that will fire with the list of inserted
                 documents.
        :rtype: twisted.internet.defer.Deferred
        """
        insertable = yield self._get_insertable_docs()
        for doc_fields in insertable:
            method = self._insert_decrypted_local_doc
            # FIXME: This is used only because SQLCipherU1DBSync is synchronous
            # When adbapi is used there is no need for an external thread
            # Without this the reactor can freeze and fail docs download
            yield threads.deferToThread(method, *doc_fields)
        defer.returnValue(insertable)

    def _delete_processed_docs(self, inserted):
        """
        Delete from the sync db documents that have been processed.

        :param inserted: List of documents inserted in the previous process
                         step.
        :type inserted: list

        :return: A list of deferreds that will fire when each operation in the
                 database has finished.
        :rtype: twisted.internet.defer.DeferredList
        """
        deferreds = []
        for doc_id, doc_rev, _, _, _, _ in inserted:
            deferreds.append(
                self._delete_received_doc(doc_id))
        if not deferreds:
            return defer.succeed(None)
        return defer.gatherResults(deferreds)

    def _insert_decrypted_local_doc(self, doc_id, doc_rev, content,
                                    gen, trans_id, idx):
        """
        Insert the decrypted document into the local replica.

        Make use of the passed callback `insert_doc_cb` passed to the caller
        by u1db sync.

        :param doc_id: The document id.
        :type doc_id: str
        :param doc_rev: The document revision.
        :type doc_rev: str
        :param content: The serialized content of the document.
        :type content: str
        :param gen: The generation corresponding to the modification of that
                    document.
        :type gen: int
        :param trans_id: The transaction id corresponding to the modification
                         of that document.
        :type trans_id: str
        """
        # could pass source_replica in params for callback chain
        logger.debug("Sync decrypter pool: inserting doc in local db: "
                     "%s:%s %s" % (doc_id, doc_rev, gen))

        # convert deleted documents to avoid error on document creation
        if content == 'null':
            content = None
        doc = SoledadDocument(doc_id, doc_rev, content)
        gen = int(gen)
        self._insert_doc_cb(doc, gen, trans_id)

        # store info about processed docs
        self._last_inserted_idx = idx
        self._processed_docs += 1

    def _init_db(self):
        """
        Empty the received docs table of the sync database.

        :return: A deferred that will fire when the operation in the database
                 has finished.
        :rtype: twisted.internet.defer.Deferred
        """
        query = "DELETE FROM %s WHERE 1" % (self.TABLE_NAME,)
        return self._runOperation(query)

    @defer.inlineCallbacks
    def _collect_async_decryption_results(self):
        """
        Collect the results of the asynchronous doc decryptions and re-raise
        any exception raised by a multiprocessing async decryption call.

        :raise Exception: Raised if an async call has raised an exception.
        """
        async_results = self._async_results[:]
        for res in async_results:
            if res.ready():
                # XXX: might raise an exception!
                yield self._decrypt_doc_cb(res.get())
                self._async_results.remove(res)

    @defer.inlineCallbacks
    def _decrypt_and_recurse(self):
        """
        Decrypt the documents received from remote replica and insert them
        into the local one.

        This method implicitelly returns a defferred (see the decorator
        above). It should only be called by _launch_decrypt_and_process().
        because this way any exceptions raised here will be stored by the
        errback attached to the deferred returned.

        :return: A deferred which will fire after all decrypt, process and
                 delete operations have been executed.
        :rtype: twisted.internet.defer.Deferred
        """
        processed = self._processed_docs
        pending = self._docs_to_process

        if processed < pending:
            yield self._async_decrypt_received_docs()
            yield self._collect_async_decryption_results()
            docs = yield self._process_decrypted_docs()
            yield self._delete_processed_docs(docs)
            # recurse
            self._delayed_call = reactor.callLater(
                self.DECRYPT_LOOP_PERIOD,
                self._launch_decrypt_and_recurse)
        else:
            self._finish()

    def _finish(self):
        self._processed_docs = 0
        self._last_inserted_idx = 0
        self._deferred.callback(None)
