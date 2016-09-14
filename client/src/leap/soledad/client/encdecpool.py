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
