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


import json
import logging
from uuid import uuid4

from twisted.internet.task import LoopingCall
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
        self._delayed_call = None
        self._started = False

    def start(self):
        self._started = True

    def stop(self):
        self._started = False
        # maybe cancel the next delayed call
        if self._delayed_call \
                and not self._delayed_call.called:
            self._delayed_call.cancel()

    @property
    def running(self):
        return self._started

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
        # TODO delete already synced files from database

    def start(self):
        """
        Start the encrypter pool.
        """
        SyncEncryptDecryptPool.start(self)
        logger.debug("Starting the encryption loop...")

    def stop(self):
        """
        Stop the encrypter pool.
        """

        SyncEncryptDecryptPool.stop(self)

    def encrypt_doc(self, doc):
        """
        Encrypt document asynchronously then insert it on
        local staging database.

        :param doc: The document to be encrypted.
        :type doc: SoledadDocument
        """
        soledad_assert(self._crypto is not None, "need a crypto object")
        docstr = doc.get_json()
        key = self._crypto.doc_passphrase(doc.doc_id)
        secret = self._crypto.secret
        args = doc.doc_id, doc.rev, docstr, key, secret
        # encrypt asynchronously
        # TODO use dedicated threadpool / move to ampoule
        d = threads.deferToThread(
            encrypt_doc_task, *args)
        d.addCallback(self._encrypt_doc_cb)
        return d

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
    :param content: The encrypted content of the document as JSON dict.
    :type content: dict
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
                  "trans_id, encrypted, idx, sync_id"

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

        self._loop = LoopingCall(self._decrypt_and_recurse)

    def start(self, docs_to_process):
        """
        Set the number of documents we expect to process.

        This should be called by the during the sync exchange process as soon
        as we know how many documents are arriving from the server.

        :param docs_to_process: The number of documents to process.
        :type docs_to_process: int
        """
        SyncEncryptDecryptPool.start(self)
        self._decrypted_docs_indexes = set()
        self._sync_id = uuid4().hex
        self._docs_to_process = docs_to_process
        self._deferred = defer.Deferred()
        d = self._init_db()
        d.addCallback(lambda _: self._loop.start(self.DECRYPT_LOOP_PERIOD))
        return d

    def stop(self):
        if self._loop.running:
            self._loop.stop()
        self._finish()
        SyncEncryptDecryptPool.stop(self)

    def _init_db(self):
        """
        Ensure sync_id column is present then
        Empty the received docs table of the sync database.

        :return: A deferred that will fire when the operation in the database
                 has finished.
        :rtype: twisted.internet.defer.Deferred
        """
        ensure_sync_id_column = ("ALTER TABLE %s ADD COLUMN sync_id" %
                                 self.TABLE_NAME)
        d = self._runQuery(ensure_sync_id_column)

        def empty_received_docs(_):
            query = "DELETE FROM %s WHERE sync_id <> ?" % (self.TABLE_NAME,)
            return self._runOperation(query, (self._sync_id,))

        d.addCallbacks(empty_received_docs, empty_received_docs)
        return d

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
        Decrypt and insert a received document into local staging area to be
        processed later on.

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

        :return: A deferred that will fire after the decrypted document has
                 been inserted in the sync db.
        :rtype: twisted.internet.defer.Deferred
        """
        soledad_assert(self._crypto is not None, "need a crypto object")

        key = self._crypto.doc_passphrase(doc_id)
        secret = self._crypto.secret
        args = doc_id, doc_rev, content, gen, trans_id, key, secret, idx
        # decrypt asynchronously
        # TODO use dedicated threadpool / move to ampoule
        d = threads.deferToThread(
            decrypt_doc_task, *args)
        # callback will insert it for later processing
        d.addCallback(self._decrypt_doc_cb)
        return d

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
        query = "INSERT OR REPLACE INTO '%s' VALUES (?, ?, ?, ?, ?, ?, ?, ?)" \
                % self.TABLE_NAME
        d = self._runOperation(
            query, (doc_id, doc_rev, content, gen, trans_id, 0,
                    idx, self._sync_id))
        d.addCallback(lambda _: self._decrypted_docs_indexes.add(idx))
        return d

    def _delete_received_docs(self, doc_ids):
        """
        Delete a list of received docs after get them inserted into the db.

        :param doc_id: Document ID list.
        :type doc_id: list

        :return: A deferred that will fire when the operation in the database
                 has finished.
        :rtype: twisted.internet.defer.Deferred
        """
        placeholders = ', '.join('?' for _ in doc_ids)
        query = "DELETE FROM '%s' WHERE doc_id in (%s)" \
                % (self.TABLE_NAME, placeholders)
        return self._runOperation(query, (doc_ids))

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
        return self.insert_received_doc(
            doc_id, rev, content, gen, trans_id, idx)

    def _get_docs(self, encrypted=None, sequence=None):
        """
        Get documents from the received docs table in the sync db.

        :param encrypted: If not None, only return documents with encrypted
                          field equal to given parameter.
        :type encrypted: bool or None
        :param order_by: The name of the field to order results.

        :return: A deferred that will fire with the results of the database
                 query.
        :rtype: twisted.internet.defer.Deferred
        """
        query = "SELECT doc_id, rev, content, gen, trans_id, encrypted, " \
                "idx FROM %s" % self.TABLE_NAME
        parameters = []
        if encrypted or sequence:
            query += " WHERE sync_id = ? and"
            parameters += [self._sync_id]
        if encrypted:
            query += " encrypted = ?"
            parameters += [int(encrypted)]
        if sequence:
            query += " idx in (" + ', '.join('?' * len(sequence)) + ")"
            parameters += [int(i) for i in sequence]
        query += " ORDER BY idx ASC"
        return self._runQuery(query, parameters)

    @defer.inlineCallbacks
    def _get_insertable_docs(self):
        """
        Return a list of non-encrypted documents ready to be inserted.

        :return: A deferred that will fire with the list of insertable
                 documents.
        :rtype: twisted.internet.defer.Deferred
        """
        # Here, check in memory what are the insertable indexes that can
        # form a sequence starting from the last inserted index
        sequence = []
        insertable_docs = []
        next_index = self._last_inserted_idx + 1
        while next_index in self._decrypted_docs_indexes:
            sequence.append(str(next_index))
            next_index += 1
        # Then fetch all the ones ready for insertion.
        if sequence:
            insertable_docs = yield self._get_docs(encrypted=False,
                                                   sequence=sequence)
        defer.returnValue(insertable_docs)

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
        processed_docs_ids = []
        for doc_fields in insertable:
            method = self._insert_decrypted_local_doc
            # FIXME: This is used only because SQLCipherU1DBSync is synchronous
            # When adbapi is used there is no need for an external thread
            # Without this the reactor can freeze and fail docs download
            yield threads.deferToThread(method, *doc_fields)
            processed_docs_ids.append(doc_fields[0])
        yield self._delete_received_docs(processed_docs_ids)

    def _insert_decrypted_local_doc(self, doc_id, doc_rev, content,
                                    gen, trans_id, encrypted, idx):
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
        if not self.running:
            defer.returnValue(None)
        processed = self._processed_docs
        pending = self._docs_to_process

        if processed < pending:
            yield self._process_decrypted_docs()
        else:
            self._finish()

    def _finish(self):
        self._processed_docs = 0
        self._last_inserted_idx = 0
        self._decrypted_docs_indexes = set()
        if not self._deferred.called:
            self._deferred.callback(None)
