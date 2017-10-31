# -*- coding: utf-8 -*-
# sql.py
# Copyright (C) 2017 LEAP
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
Local blobs backend on SQLCipher
"""
import os
import binascii
from functools import partial
from twisted.internet import defer
from twisted.logger import Logger
from twisted.enterprise import adbapi
from leap.common.files import mkdir_p
from .. import sqlcipher
from .. import pragmas
from io import BytesIO
logger = Logger()


class SyncStatus:
    SYNCED = 1
    PENDING_UPLOAD = 2
    PENDING_DOWNLOAD = 3
    FAILED_UPLOAD = 4
    FAILED_DOWNLOAD = 5
    UNAVAILABLE_STATUSES = (3, 5)


class SQLiteBlobBackend(object):

    concurrency_limit = 10

    def __init__(self, path, key=None, user=None):
        dbname = '%s_blobs.db' % (user or 'soledad')
        self.path = os.path.abspath(
            os.path.join(path, dbname))
        mkdir_p(os.path.dirname(self.path))
        if not key:
            raise ValueError('key cannot be None')
        backend = 'pysqlcipher.dbapi2'
        opts = sqlcipher.SQLCipherOptions(
            '/tmp/ignored', binascii.b2a_hex(key),
            is_raw_key=True, create=True)
        openfun = partial(pragmas.set_init_pragmas, opts=opts,
                          schema_func=_init_tables)

        self.dbpool = ConnectionPool(
            backend, self.path, check_same_thread=False, timeout=5,
            cp_openfun=openfun, cp_min=2, cp_max=2, cp_name='blob_pool')

    def close(self):
        from twisted._threads import AlreadyQuit
        try:
            self.dbpool.close()
        except AlreadyQuit:
            pass

    @defer.inlineCallbacks
    def put(self, blob_id, blob_fd, size=None,
            namespace=''):
        logger.info("Saving blob in local database...")
        insert = 'INSERT INTO blobs (blob_id, namespace, payload)'
        insert += ' VALUES (?, ?, zeroblob(?))'
        values = (blob_id, namespace, size)
        irow = yield self.dbpool.insertAndGetLastRowid(insert, values)
        yield self.dbpool.write_blob('blobs', 'payload', irow, blob_fd)
        logger.info("Finished saving blob in local database.")

    @defer.inlineCallbacks
    def get(self, blob_id, namespace=''):
        # TODO we can also stream the blob value using sqlite
        # incremental interface for blobs - and just return the raw fd instead
        select = 'SELECT payload FROM blobs WHERE blob_id = ? AND namespace= ?'
        values = (blob_id, namespace,)
        result = yield self.dbpool.runQuery(select, values)
        if result:
            defer.returnValue(BytesIO(str(result[0][0])))

    @defer.inlineCallbacks
    def get_sync_status(self, blob_id):
        select = 'SELECT sync_status, retries FROM sync_state WHERE blob_id= ?'
        result = yield self.dbpool.runQuery(select, (blob_id,))
        if result:
            defer.returnValue((result[0][0], result[0][1]))

    @defer.inlineCallbacks
    def get_sync_progress(self):
        query = 'SELECT sync_status, COUNT(sync_status) FROM sync_state'
        query += ' GROUP BY sync_status'

        def by_value(value):
            statuses = SyncStatus.__dict__.items()
            return filter(lambda x: x[1] == value, statuses)[0][0]
        result = yield self.dbpool.runQuery(query)
        if result:
            defer.returnValue(dict([(by_value(r[0]), r[1]) for r in result]))
        else:
            defer.returnValue([])

    @defer.inlineCallbacks
    def list(self, namespace=''):
        query = 'select blob_id from blobs where namespace = ?'
        values = (namespace,)
        result = yield self.dbpool.runQuery(query, values)
        if result:
            defer.returnValue([b_id[0] for b_id in result])
        else:
            defer.returnValue([])

    @defer.inlineCallbacks
    def list_status(self, sync_status, namespace=''):
        query = 'select blob_id from sync_state where sync_status = ?'
        query += 'AND namespace = ?'
        values = (sync_status, namespace,)
        result = yield self.dbpool.runQuery(query, values)
        if result:
            defer.returnValue([b_id[0] for b_id in result])
        else:
            defer.returnValue([])

    @defer.inlineCallbacks
    def update_sync_status(self, blob_id, sync_status, namespace=""):
        query = 'SELECT sync_status FROM sync_state WHERE blob_id = ?'
        result = yield self.dbpool.runQuery(query, (blob_id,))

        if not result:
            insert = 'INSERT INTO sync_state'
            insert += ' (blob_id, namespace, sync_status)'
            insert += ' VALUES (?, ?, ?)'
            values = (blob_id, namespace, sync_status)
            yield self.dbpool.runOperation(insert, values)
            return

        update = 'UPDATE sync_state SET sync_status = ? WHERE blob_id = ?'
        values = (sync_status, blob_id,)
        result = yield self.dbpool.runOperation(update, values)

    def update_batch_sync_status(self, blob_id_list, sync_status,
                                 namespace=''):
        insert = 'INSERT INTO sync_state (blob_id, namespace, sync_status)'
        first_blob_id, blob_id_list = blob_id_list[0], blob_id_list[1:]
        insert += ' VALUES (?, ?, ?)'
        values = (first_blob_id, namespace, sync_status)
        for blob_id in blob_id_list:
            insert += ', (?, ?, ?)'
            values += (blob_id, namespace, sync_status)
        return self.dbpool.runQuery(insert, values)

    def increment_retries(self, blob_id):
        query = 'update sync_state set retries = retries + 1 where blob_id = ?'
        return self.dbpool.runQuery(query, (blob_id,))

    @defer.inlineCallbacks
    def list_namespaces(self):
        query = 'select namespace from blobs'
        result = yield self.dbpool.runQuery(query)
        if result:
            defer.returnValue([namespace[0] for namespace in result])
        else:
            defer.returnValue([])

    @defer.inlineCallbacks
    def exists(self, blob_id, namespace=''):
        query = 'SELECT blob_id from blobs WHERE blob_id = ? AND namespace= ?'
        result = yield self.dbpool.runQuery(query, (blob_id, namespace,))
        defer.returnValue(bool(len(result)))

    def delete(self, blob_id, namespace=''):
        query = 'DELETE FROM blobs WHERE blob_id = ? AND namespace = ?'
        return self.dbpool.runQuery(query, (blob_id, namespace,))


def _init_tables(conn):
    # unified init for running under the same lock
    _init_blob_table(conn)
    _init_sync_table(conn)


def _init_sync_table(conn):
    maybe_create = """
        CREATE TABLE IF NOT EXISTS
        sync_state (
        blob_id PRIMARY KEY,
        namespace TEXT,
        sync_status INT default %s,
        retries INT default 0)"""
    default_status = SyncStatus.PENDING_UPLOAD
    maybe_create %= default_status
    conn.execute(maybe_create)


def _init_blob_table(conn):
    maybe_create = (
        "CREATE TABLE IF NOT EXISTS "
        "blobs ("
        "blob_id PRIMARY KEY, "
        "payload BLOB)")
    conn.execute(maybe_create)
    columns = [row[1] for row in conn.execute("pragma"
               " table_info(blobs)").fetchall()]
    if 'namespace' not in columns:
        # namespace migration
        conn.execute('ALTER TABLE blobs ADD COLUMN namespace TEXT')
    if 'sync_status' not in columns:
        # sync status migration
        default_status = SyncStatus.PENDING_UPLOAD
        sync_column = 'ALTER TABLE blobs ADD COLUMN sync_status INT default %s'
        sync_column %= default_status
        conn.execute(sync_column)
        conn.execute('ALTER TABLE blobs ADD COLUMN retries INT default 0')


class ConnectionPool(adbapi.ConnectionPool):

    def insertAndGetLastRowid(self, *args, **kwargs):
        """
        Execute an SQL query and return the last rowid.

        See: https://sqlite.org/c3ref/last_insert_rowid.html
        """
        return self.runInteraction(
            self._insertAndGetLastRowid, *args, **kwargs)

    def _insertAndGetLastRowid(self, trans, *args, **kw):
        trans.execute(*args, **kw)
        return trans.lastrowid

    def blob(self, table, column, irow, flags):
        """
        Open a BLOB for incremental I/O.

        Return a handle to the BLOB that would be selected by:

          SELECT column FROM table WHERE rowid = irow;

        See: https://sqlite.org/c3ref/blob_open.html

        :param table: The table in which to lookup the blob.
        :type table: str
        :param column: The column where the BLOB is located.
        :type column: str
        :param rowid: The rowid of the BLOB.
        :type rowid: int
        :param flags: If zero, BLOB is opened for read-only. If non-zero,
                      BLOB is opened for RW.
        :type flags: int

        :return: A BLOB handle.
        :rtype: pysqlcipher.dbapi.Blob
        """
        return self.runInteraction(self._blob, table, column, irow, flags)

    def write_blob(self, table, column, irow, blob_fd):
        return self.runInteraction(self._write_blob, table, column, irow,
                                   blob_fd)

    def _write_blob(self, trans, table, column, irow, blob_fd):
        blob_fd.seek(0)
        with trans._connection.blob(table, column, irow, 1) as handle:
            data = blob_fd.read(2**12)
            while data:
                handle.write(data)
                data = blob_fd.read(2**12)

    def _blob(self, trans, table, column, irow, flags):
        # TODO: should not use transaction private variable here
        handle = trans._connection.blob(table, column, irow, flags)
        return handle
