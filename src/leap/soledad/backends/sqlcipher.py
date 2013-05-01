# -*- coding: utf-8 -*-
# sqlcipher.py
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


"""A U1DB backend that uses SQLCipher as its persistence layer."""

import os
import time


from u1db.backends import sqlite_backend
from pysqlcipher import dbapi2
from u1db import (
    errors,
)
from leap.soledad.backends.leap_backend import LeapDocument


# Monkey-patch u1db.backends.sqlite_backend with pysqlcipher.dbapi2
sqlite_backend.dbapi2 = dbapi2


def open(path, password, create=True, document_factory=None, crypto=None):
    """Open a database at the given location.

    Will raise u1db.errors.DatabaseDoesNotExist if create=False and the
    database does not already exist.

    @param path: The filesystem path for the database to open.
    @param type: str
    @param create: True/False, should the database be created if it doesn't
        already exist?
    @param type: bool
    @param document_factory: A function that will be called with the same
        parameters as Document.__init__.
    @type document_factory: callable

    @return: An instance of Database.
    @rtype SQLCipherDatabase
    """
    return SQLCipherDatabase.open_database(
        path, password, create=create, document_factory=document_factory,
        crypto=crypto)


class DatabaseIsNotEncrypted(Exception):
    """
    Exception raised when trying to open non-encrypted databases.
    """
    pass


class SQLCipherDatabase(sqlite_backend.SQLitePartialExpandDatabase):
    """A U1DB implementation that uses SQLCipher as its persistence layer."""

    _index_storage_value = 'expand referenced encrypted'

    @classmethod
    def set_pragma_key(cls, db_handle, key):
        db_handle.cursor().execute("PRAGMA key = '%s'" % key)

    def __init__(self, sqlcipher_file, password, document_factory=None,
                 crypto=None):
        """
        Create a new sqlcipher file.

        @param sqlcipher_file: The path for the SQLCipher file.
        @type sqlcipher_file: str
        @param password: The password that protects the SQLCipher db.
        @type password: str
        @param document_factory: A function that will be called with the same
            parameters as Document.__init__.
        @type document_factory: callable
        @param crypto: An instance of SoledadCrypto so we can encrypt/decrypt
            document contents when syncing.
        @type crypto: soledad.crypto.SoledadCrypto
        """
        self._check_if_db_is_encrypted(sqlcipher_file)
        self._db_handle = dbapi2.connect(sqlcipher_file)
        SQLCipherDatabase.set_pragma_key(self._db_handle, password)
        self._real_replica_uid = None
        self._ensure_schema()
        self._crypto = crypto

        def factory(doc_id=None, rev=None, json='{}', has_conflicts=False,
                    syncable=True):
            return LeapDocument(doc_id=doc_id, rev=rev, json=json,
                                has_conflicts=has_conflicts,
                                syncable=syncable)
        self.set_document_factory(factory)

    def _check_if_db_is_encrypted(self, sqlcipher_file):
        """
        Verify if loca file is an encrypted database.

        @param sqlcipher_file: The path for the SQLCipher file.
        @type sqlcipher_file: str

        @return: True if the database is encrypted, False otherwise.
        @rtype: bool
        """
        if not os.path.exists(sqlcipher_file):
            return
        else:
            try:
                # try to open an encrypted database with the regular u1db
                # backend should raise a DatabaseError exception.
                sqlite_backend.SQLitePartialExpandDatabase(sqlcipher_file)
                raise DatabaseIsNotEncrypted()
            except dbapi2.DatabaseError:
                pass

    @classmethod
    def _open_database(cls, sqlcipher_file, password, document_factory=None,
                       crypto=None):
        """
        Open a SQLCipher database.

        @param sqlcipher_file: The path for the SQLCipher file.
        @type sqlcipher_file: str
        @param password: The password that protects the SQLCipher db.
        @type password: str
        @param document_factory: A function that will be called with the same
            parameters as Document.__init__.
        @type document_factory: callable
        @param crypto: An instance of SoledadCrypto so we can encrypt/decrypt
            document contents when syncing.
        @type crypto: soledad.crypto.SoledadCrypto

        @return: The database object.
        @rtype: SQLCipherDatabase
        """
        if not os.path.isfile(sqlcipher_file):
            raise errors.DatabaseDoesNotExist()
        tries = 2
        while True:
            # Note: There seems to be a bug in sqlite 3.5.9 (with python2.6)
            #       where without re-opening the database on Windows, it
            #       doesn't see the transaction that was just committed
            db_handle = dbapi2.connect(sqlcipher_file)
            SQLCipherDatabase.set_pragma_key(db_handle, password)
            c = db_handle.cursor()
            v, err = cls._which_index_storage(c)
            db_handle.close()
            if v is not None:
                break
            # possibly another process is initializing it, wait for it to be
            # done
            if tries == 0:
                raise err  # go for the richest error?
            tries -= 1
            time.sleep(cls.WAIT_FOR_PARALLEL_INIT_HALF_INTERVAL)
        return SQLCipherDatabase._sqlite_registry[v](
            sqlcipher_file, password, document_factory=document_factory,
            crypto=crypto)

    @classmethod
    def open_database(cls, sqlcipher_file, password, create, backend_cls=None,
                      document_factory=None, crypto=None):
        """
        Open a SQLCipher database.

        @param sqlcipher_file: The path for the SQLCipher file.
        @type sqlcipher_file: str
        @param password: The password that protects the SQLCipher db.
        @type password: str
        @param create: Should the datbase be created if it does not already
            exist?
        @type: bool
        @param backend_cls: A class to use as backend.
        @type backend_cls: type
        @param document_factory: A function that will be called with the same
            parameters as Document.__init__.
        @type document_factory: callable
        @param crypto: An instance of SoledadCrypto so we can encrypt/decrypt
            document contents when syncing.
        @type crypto: soledad.crypto.SoledadCrypto

        @return: The database object.
        @rtype: SQLCipherDatabase
        """
        try:
            return cls._open_database(sqlcipher_file, password,
                                      document_factory=document_factory,
                                      crypto=crypto)
        except errors.DatabaseDoesNotExist:
            if not create:
                raise
            # TODO: remove backend class from here.
            if backend_cls is None:
                # default is SQLCipherPartialExpandDatabase
                backend_cls = SQLCipherDatabase
            return backend_cls(sqlcipher_file, password,
                               document_factory=document_factory,
                               crypto=crypto)

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
        from u1db.sync import Synchronizer
        from leap.soledad.backends.leap_backend import LeapSyncTarget
        return Synchronizer(
            self,
            LeapSyncTarget(url,
                           creds=creds,
                           crypto=self._crypto)).sync(autocreate=autocreate)

    def _extra_schema_init(self, c):
        """
        Add any extra fields, etc to the basic table definitions.

        @param c: The cursor for querying the database.
        @type c: dbapi2.cursor
        """
        c.execute(
            'ALTER TABLE document '
            'ADD COLUMN syncable BOOL NOT NULL DEFAULT TRUE')

    def _put_and_update_indexes(self, old_doc, doc):
        """
        Update a document and all indexes related to it.

        @param old_doc: The old version of the document.
        @type old_doc: u1db.Document
        @param doc: The new version of the document.
        @type doc: u1db.Document
        """
        sqlite_backend.SQLitePartialExpandDatabase._put_and_update_indexes(
            self, old_doc, doc)
        c = self._db_handle.cursor()
        c.execute('UPDATE document SET syncable=? '
                  'WHERE doc_id=?',
                  (doc.syncable, doc.doc_id))

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
        doc = sqlite_backend.SQLitePartialExpandDatabase._get_doc(
            self, doc_id, check_for_conflicts)
        if doc:
            c = self._db_handle.cursor()
            c.execute('SELECT syncable FROM document '
                      'WHERE doc_id=?',
                      (doc.doc_id,))
            result = c.fetchone()
            doc.syncable = bool(result[0])
        return doc

sqlite_backend.SQLiteDatabase.register_implementation(SQLCipherDatabase)
