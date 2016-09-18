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


from twisted.internet import threads
from twisted.internet import defer

from leap.soledad.common import soledad_assert
from leap.soledad.common.log import getLogger

from leap.soledad.client.crypto import encrypt_docstr
from leap.soledad.client.crypto import decrypt_doc_dict


logger = getLogger(__name__)


#
# Encrypt pool of workers
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
        logger.debug("starting the encryption loop...")

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
            logger.debug("found doc on sync db: %s" % doc_id)
            val = result.pop()
            defer.returnValue(val[0])
        logger.debug("did not find doc on sync db: %s" % doc_id)
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
