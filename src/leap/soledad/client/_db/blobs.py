# -*- coding: utf-8 -*-
# _blobs.py
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
Clientside BlobBackend Storage.
"""

from urlparse import urljoin

import binascii
import os
import json
import base64

from io import BytesIO
from functools import partial

from twisted.logger import Logger
from twisted.enterprise import adbapi
from twisted.internet import defer
from twisted.internet import reactor
from twisted.internet import error

import treq

from leap.soledad.common.errors import SoledadError
from leap.common.files import mkdir_p

from .._document import BlobDoc
from .._crypto import DocInfo
from .._crypto import InvalidBlob
from .._crypto import BlobEncryptor
from .._crypto import BlobDecryptor
from .._crypto import EncryptionSchemeNotImplementedException
from .._http import HTTPClient
from .._pipes import TruncatedTailPipe
from .._pipes import PreamblePipe

from . import pragmas
from . import sqlcipher


logger = Logger()
FIXED_REV = 'ImmutableRevision'  # Blob content is immutable


class BlobAlreadyExistsError(SoledadError):
    pass


class BlobNotFoundError(SoledadError):
    pass


class InvalidFlagsError(SoledadError):
    pass


class SyncStatus:
    SYNCED = 1
    PENDING_UPLOAD = 2
    PENDING_DOWNLOAD = 3
    FAILED_UPLOAD = 4
    FAILED_DOWNLOAD = 5
    UNAVAILABLE_STATUSES = (3, 5)


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


def check_http_status(code, blob_id=None, flags=None):
    if code == 404:
        raise BlobNotFoundError(blob_id)
    if code == 409:
        raise BlobAlreadyExistsError(blob_id)
    elif code == 406:
        raise InvalidFlagsError((blob_id, flags))
    elif code != 200:
        raise SoledadError("Server Error: %s" % code)


class RetriableTransferError(Exception):
    pass


def sleep(seconds):
    d = defer.Deferred()
    reactor.callLater(seconds, d.callback, None)
    return d


MAX_WAIT = 60  # In seconds. Max time between retries


@defer.inlineCallbacks
def with_retry(func, *args, **kwargs):
    retry_wait = 1
    retriable_errors = (error.ConnectError, error.ConnectionClosed,
                        RetriableTransferError,)
    while True:
        try:
            yield func(*args, **kwargs)
            break
        except retriable_errors:
            yield sleep(retry_wait)
            retry_wait = min(retry_wait + 10, MAX_WAIT)


class DecrypterBuffer(object):

    def __init__(self, blob_id, secret, tag):
        self.doc_info = DocInfo(blob_id, FIXED_REV)
        self.secret = secret
        self.tag = tag
        self.preamble_pipe = PreamblePipe(self._make_decryptor)
        self.decrypter = None

    def _make_decryptor(self, preamble):
        try:
            self.decrypter = BlobDecryptor(
                self.doc_info, preamble,
                secret=self.secret,
                armor=False,
                start_stream=False,
                tag=self.tag)
            return TruncatedTailPipe(self.decrypter, tail_size=len(self.tag))
        except EncryptionSchemeNotImplementedException:
            # If we do not support the provided encryption scheme, than that's
            # something for the application using soledad to handle. This is
            # the case on asymmetrically encrypted documents on IncomingBox.
            self.raw_data = BytesIO()
            return self.raw_data

    def write(self, data):
        self.preamble_pipe.write(data)

    def close(self):
        if self.decrypter:
            real_size = self.decrypter.decrypted_content_size
            return self.decrypter.endStream(), real_size
        else:
            return self.raw_data, self.raw_data.tell()


class BlobManager(object):
    """
    The BlobManager can list, put, get, set flags and synchronize blobs stored
    in local and remote storages.
    """
    max_retries = 3
    concurrency_limit = 3

    def __init__(
            self, local_path, remote, key, secret, user, token=None,
            cert_file=None):
        """
        Initialize the blob manager.

        :param local_path: The path for the local blobs database.
        :type local_path: str
        :param remote: The URL of the remote storage.
        :type remote: str
        :param secret: The secret used to encrypt/decrypt blobs.
        :type secret: str
        :param user: The uuid of the user.
        :type user: str
        :param token: The access token for interacting with remote storage.
        :type token: str
        :param cert_file: The path to the CA certificate file.
        :type cert_file: str
        """
        if local_path:
            mkdir_p(os.path.dirname(local_path))
            self.local = SQLiteBlobBackend(local_path, key=key, user=user)
        self.remote = remote
        self.secret = secret
        self.user = user
        self._client = HTTPClient(user, token, cert_file)

    def close(self):
        if hasattr(self, 'local') and self.local:
            return self.local.close()

    def count(self, namespace=''):
        """
        Count the number of blobs.

        :param namespace:
            Optional parameter to restrict operation to a given namespace.
        :type namespace: str
        :return: A deferred that fires with a dict parsed from the JSON
            response, which `count` key has the number of blobs as value.
            Eg.: {"count": 42}
        :rtype: twisted.internet.defer.Deferred
        """
        return self.remote_list(namespace=namespace, only_count=True)

    @defer.inlineCallbacks
    def remote_list(self, namespace='', order_by=None,
                    filter_flag=False, only_count=False):
        """
        List blobs from server, with filtering and ordering capabilities.

        :param namespace:
            Optional parameter to restrict operation to a given namespace.
        :type namespace: str
        :param order_by:
            Optional parameter to order results. Possible values are:
            date or +date - Ascending order (older first)
            -date - Descending order (newer first)
        :type order_by: str
        :param filter_flag:
            Optional parameter to filter listing to results containing the
            specified tag.
        :type filter_flag: leap.soledad.common.blobs.Flags
        :param only_count:
            Optional paramter to return only the number of blobs found.
        :type only_count: bool
        :return: A deferred that fires with a list parsed from the JSON
            response, holding the requested list of blobs.
            Eg.: ['blob_id1', 'blob_id2']
        :rtype: twisted.internet.defer.Deferred
        """
        uri = urljoin(self.remote, self.user + '/')
        params = {'namespace': namespace} if namespace else {}
        if order_by:
            params['order_by'] = order_by
        if filter_flag:
            params['filter_flag'] = filter_flag
        if only_count:
            params['only_count'] = only_count
        response = yield self._client.get(uri, params=params)
        check_http_status(response.code)
        defer.returnValue((yield response.json()))

    def local_list(self, namespace='', sync_status=None):
        return self.local.list(namespace, sync_status)

    @defer.inlineCallbacks
    def refresh_sync_status_from_server(self, namespace=''):
        d1 = self.remote_list(namespace=namespace)
        d2 = self.local_list(namespace=namespace)
        remote_list, local_list = yield defer.gatherResults([d1, d2])
        pending_download_ids = tuple(set(remote_list) - set(local_list))
        yield self.local.update_batch_sync_status(
            pending_download_ids,
            SyncStatus.PENDING_DOWNLOAD,
            namespace=namespace)

    @defer.inlineCallbacks
    def send_missing(self, namespace=''):
        """
        Compare local and remote blobs and send what's missing in server.

        :param namespace:
            Optional parameter to restrict operation to a given namespace.
        :type namespace: str
        """
        d = self.local_list(namespace=namespace,
                            sync_status=SyncStatus.PENDING_UPLOAD)
        missing = yield d
        total = len(missing)
        logger.info("Will send %d blobs to server." % total)
        deferreds = []
        semaphore = defer.DeferredSemaphore(self.concurrency_limit)

        def release(result):
            semaphore.release()
            return result

        for i in xrange(total):
            yield semaphore.acquire()
            blob_id = missing.pop()
            d = with_retry(self.__send_one, blob_id, namespace, i, total)
            d.addCallbacks(release, release)
            deferreds.append(d)
        yield defer.gatherResults(deferreds)

    @defer.inlineCallbacks
    def __send_one(self, blob_id, namespace, i, total):
            logger.info("Sending blob to server (%d/%d): %s"
                        % (i, total, blob_id))
            fd = yield self.local.get(blob_id, namespace=namespace)
            try:
                yield self._encrypt_and_upload(blob_id, fd)
                yield self.local.update_sync_status(blob_id, SyncStatus.SYNCED)
            except Exception as e:
                yield self.local.increment_retries(blob_id)
                _, retries = yield self.local.get_sync_status(blob_id)
                if retries > self.max_retries:
                    failed_upload = SyncStatus.FAILED_UPLOAD
                    yield self.local.update_sync_status(blob_id, failed_upload)
                raise e

    @defer.inlineCallbacks
    def fetch_missing(self, namespace=''):
        """
        Compare local and remote blobs and fetch what's missing in local
        storage.

        :param namespace:
            Optional parameter to restrict operation to a given namespace.
        :type namespace: str
        """
        # TODO: Use something to prioritize user requests over general new docs
        d = self.local_list(namespace=namespace,
                            sync_status=SyncStatus.PENDING_DOWNLOAD)
        docs_we_want = yield d
        total = len(docs_we_want)
        logger.info("Will fetch %d blobs from server." % total)
        deferreds = []
        semaphore = defer.DeferredSemaphore(self.concurrency_limit)

        def release(result):
            semaphore.release()
            return result

        for i in xrange(len(docs_we_want)):
            yield semaphore.acquire()
            blob_id = docs_we_want.pop()
            logger.info("Fetching blob (%d/%d): %s" % (i, total, blob_id))
            d = with_retry(self.get, blob_id, namespace)
            d.addCallbacks(release, release)
            deferreds.append(d)
        yield defer.gatherResults(deferreds)

    @defer.inlineCallbacks
    def sync(self, namespace=''):
        try:
            yield self.refresh_sync_status_from_server(namespace)
            yield self.fetch_missing(namespace)
            yield self.send_missing(namespace)
        except defer.FirstError as e:
            e.subFailure.raiseException()

    @defer.inlineCallbacks
    def put(self, doc, size, namespace=''):
        """
        Put a blob in local storage and upload it to server.

        :param doc: A BlobDoc representing the blob.
        :type doc: leap.soledad.client._document.BlobDoc
        :param size: The size of the blob.
        :type size: int
        :param namespace:
            Optional parameter to restrict operation to a given namespace.
        :type namespace: str
        """
        if (yield self.local.exists(doc.blob_id, namespace=namespace)):
            error_message = "Blob already exists: %s" % doc.blob_id
            raise BlobAlreadyExistsError(error_message)
        fd = doc.blob_fd
        # TODO this is a tee really, but ok... could do db and upload
        # concurrently. not sure if we'd gain something.
        yield self.local.put(doc.blob_id, fd, size=size, namespace=namespace)
        # In fact, some kind of pipe is needed here, where each write on db
        # handle gets forwarded into a write on the connection handle
        fd = yield self.local.get(doc.blob_id, namespace=namespace)
        yield self._encrypt_and_upload(doc.blob_id, fd, namespace=namespace)
        yield self.local.update_sync_status(doc.blob_id, SyncStatus.SYNCED)

    @defer.inlineCallbacks
    def set_flags(self, blob_id, flags, namespace=''):
        """
        Set flags for a given blob_id.

        :param blob_id:
            Unique identifier of a blob.
        :type blob_id: str
        :param flags:
            List of flags to be set.
        :type flags: [leap.soledad.common.blobs.Flags]
        :param namespace:
            Optional parameter to restrict operation to a given namespace.
        :type namespace: str
        :return: A deferred that fires when the operation finishes.
        :rtype: twisted.internet.defer.Deferred
        """
        params = {'namespace': namespace} if namespace else None
        flagsfd = BytesIO(json.dumps(flags))
        uri = urljoin(self.remote, self.user + "/" + blob_id)
        response = yield self._client.post(uri, data=flagsfd, params=params)
        check_http_status(response.code, blob_id=blob_id, flags=flags)

    @defer.inlineCallbacks
    def get_flags(self, blob_id, namespace=''):
        """
        Get flags from a given blob_id.

        :param blob_id:
            Unique identifier of a blob.
        :type blob_id: str
        :param namespace:
            Optional parameter to restrict operation to a given namespace.
        :type namespace: str
        :return: A deferred that fires with a list parsed from JSON response.
            Eg.: [Flags.PENDING]
        :rtype: twisted.internet.defer.Deferred
        """
        uri = urljoin(self.remote, self.user + "/" + blob_id)
        params = {'namespace': namespace} if namespace else {}
        params['only_flags'] = True
        response = yield self._client.get(uri, params=params)
        check_http_status(response.code, blob_id=blob_id)
        defer.returnValue((yield response.json()))

    @defer.inlineCallbacks
    def get(self, blob_id, namespace=''):
        """
        Get the blob from local storage or, if not available, from the server.

        :param blob_id:
            Unique identifier of a blob.
        :type blob_id: str
        :param namespace:
            Optional parameter to restrict operation to a given namespace.
        :type namespace: str
        """
        local_blob = yield self.local.get(blob_id, namespace=namespace)
        if local_blob:
            logger.info("Found blob in local database: %s" % blob_id)
            defer.returnValue(local_blob)

        try:
            result = yield self._download_and_decrypt(blob_id, namespace)
        except Exception as e:
            _, retries = yield self.local.get_sync_status(blob_id)

            if isinstance(e, InvalidBlob):
                message = "Corrupted blob received from server! ID: %s\n"
                message += "Error: %r\n"
                message += "Retries: %s - Attempts left: %s\n"
                message += "This is either a bug or the contents of the "
                message += "blob have been tampered with. Please, report to "
                message += "your provider's sysadmin and submit a bug report."
                message %= (blob_id, e, retries, (self.max_retries - retries))
                logger.error(message)

            yield self.local.increment_retries(blob_id)
            if (retries + 1) >= self.max_retries:
                failed_download = SyncStatus.FAILED_DOWNLOAD
                yield self.local.update_sync_status(blob_id, failed_download)
                raise e
            else:
                raise RetriableTransferError(e)

        if not result:
            defer.returnValue(None)
        blob, size = result

        if blob:
            logger.info("Got decrypted blob of type: %s" % type(blob))
            blob.seek(0)
            yield self.local.put(blob_id, blob, size=size, namespace=namespace)
            local_blob = yield self.local.get(blob_id, namespace=namespace)
            defer.returnValue(local_blob)
        else:
            # XXX we shouldn't get here, but we will...
            # lots of ugly error handling possible:
            # 1. retry, might be network error
            # 2. try later, maybe didn't finished streaming
            # 3.. resignation, might be error while verifying
            logger.error('sorry, dunno what happened')

    @defer.inlineCallbacks
    def _encrypt_and_upload(self, blob_id, fd, namespace=''):
        # TODO ------------------------------------------
        # this is wrong, is doing 2 stages.
        # the crypto producer can be passed to
        # the uploader and react as data is written.
        # try to rewrite as a tube: pass the fd to aes and let aes writer
        # produce data to the treq request fd.
        # ------------------------------------------------
        logger.info("Staring upload of blob: %s" % blob_id)
        doc_info = DocInfo(blob_id, FIXED_REV)
        uri = urljoin(self.remote, self.user + "/" + blob_id)
        crypter = BlobEncryptor(doc_info, fd, secret=self.secret,
                                armor=False)
        fd = yield crypter.encrypt()
        params = {'namespace': namespace} if namespace else None
        response = yield self._client.put(uri, data=fd, params=params)
        check_http_status(response.code, blob_id)
        logger.info("Finished upload: %s" % (blob_id,))

    @defer.inlineCallbacks
    def _download_and_decrypt(self, blob_id, namespace=''):
        logger.info("Staring download of blob: %s" % blob_id)
        # TODO this needs to be connected in a tube
        uri = urljoin(self.remote, self.user + '/' + blob_id)
        params = {'namespace': namespace} if namespace else None
        response = yield self._client.get(uri, params=params)
        check_http_status(response.code, blob_id=blob_id)

        if not response.headers.hasHeader('Tag'):
            msg = "Server didn't send a tag header for: %s" % blob_id
            logger.error(msg)
            raise SoledadError(msg)
        tag = response.headers.getRawHeaders('Tag')[0]
        tag = base64.urlsafe_b64decode(tag)
        buf = DecrypterBuffer(blob_id, self.secret, tag)

        # incrementally collect the body of the response
        yield treq.collect(response, buf.write)
        fd, size = buf.close()
        logger.info("Finished download: (%s, %d)" % (blob_id, size))
        defer.returnValue((fd, size))

    @defer.inlineCallbacks
    def delete(self, blob_id, namespace=''):
        """
        Delete a blob from local and remote storages.

        :param blob_id:
            Unique identifier of a blob.
        :type blob_id: str
        :param namespace:
            Optional parameter to restrict operation to a given namespace.
        :type namespace: str
        :return: A deferred that fires when the operation finishes.
        :rtype: twisted.internet.defer.Deferred
        """
        logger.info("Staring deletion of blob: %s" % blob_id)
        yield self._delete_from_remote(blob_id, namespace=namespace)
        if (yield self.local.exists(blob_id, namespace=namespace)):
            yield self.local.delete(blob_id, namespace=namespace)

    @defer.inlineCallbacks
    def _delete_from_remote(self, blob_id, namespace=''):
        # TODO this needs to be connected in a tube
        uri = urljoin(self.remote, self.user + '/' + blob_id)
        params = {'namespace': namespace} if namespace else None
        response = yield self._client.delete(uri, params=params)
        check_http_status(response.code, blob_id=blob_id)
        defer.returnValue(response)


class SQLiteBlobBackend(object):

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
                          schema_func=_init_blob_table)

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
            namespace='', status=SyncStatus.PENDING_UPLOAD):
        previous_state = yield self.get_sync_status(blob_id)
        unavailable = SyncStatus.UNAVAILABLE_STATUSES
        if previous_state and previous_state[0] in unavailable:
            yield self.delete(blob_id, namespace=namespace)
            status = SyncStatus.SYNCED
        logger.info("Saving blob in local database...")
        insert = 'INSERT INTO blobs (blob_id, namespace, payload, sync_status)'
        insert += ' VALUES (?, ?, zeroblob(?), ?)'
        values = (blob_id, namespace, size, status)
        irow = yield self.dbpool.insertAndGetLastRowid(insert, values)
        yield self.dbpool.write_blob('blobs', 'payload', irow, blob_fd)
        logger.info("Finished saving blob in local database.")

    @defer.inlineCallbacks
    def get(self, blob_id, namespace=''):
        # TODO we can also stream the blob value using sqlite
        # incremental interface for blobs - and just return the raw fd instead
        select = 'SELECT payload FROM blobs WHERE blob_id = ? AND namespace= ?'
        values = (blob_id, namespace,)
        avoid_values = SyncStatus.UNAVAILABLE_STATUSES
        select += ' AND sync_status NOT IN (%s)'
        select %= ','.join(['?' for _ in avoid_values])
        values += avoid_values
        result = yield self.dbpool.runQuery(select, values)
        if result:
            defer.returnValue(BytesIO(str(result[0][0])))

    @defer.inlineCallbacks
    def get_sync_status(self, blob_id):
        select = 'SELECT sync_status, retries FROM blobs WHERE blob_id = ?'
        result = yield self.dbpool.runQuery(select, (blob_id,))
        if result:
            defer.returnValue((result[0][0], result[0][1]))

    @defer.inlineCallbacks
    def list(self, namespace='', sync_status=False):
        query = 'select blob_id from blobs where namespace = ?'
        values = (namespace,)
        if sync_status:
            query += ' and sync_status = ?'
            values += (sync_status,)
        else:
            avoid_values = SyncStatus.UNAVAILABLE_STATUSES
            query += ' AND sync_status NOT IN (%s)'
            query %= ','.join(['?' for _ in avoid_values])
            values += avoid_values
        result = yield self.dbpool.runQuery(query, values)
        if result:
            defer.returnValue([b_id[0] for b_id in result])
        else:
            defer.returnValue([])

    def update_sync_status(self, blob_id, sync_status):
        query = 'update blobs set sync_status = ? where blob_id = ?'
        values = (sync_status, blob_id,)
        return self.dbpool.runQuery(query, values)

    def update_batch_sync_status(self, blob_id_list, sync_status,
                                 namespace=''):
        insert = 'INSERT INTO blobs (blob_id, namespace, payload, sync_status)'
        first_blob_id, blob_id_list = blob_id_list[0], blob_id_list[1:]
        insert += ' VALUES (?, ?, zeroblob(0), ?)'
        values = (first_blob_id, namespace, sync_status)
        for blob_id in blob_id_list:
            insert += ', (?, ?, zeroblob(0), ?)'
            values += (blob_id, namespace, sync_status)
        return self.dbpool.runQuery(insert, values)

    def increment_retries(self, blob_id):
        query = 'update blobs set retries = retries + 1 where blob_id = ?'
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


#
# testing facilities
#

@defer.inlineCallbacks
def testit(reactor):
    # configure logging to stdout
    from twisted.python import log
    import sys
    log.startLogging(sys.stdout)

    # parse command line arguments
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('--url', default='http://localhost:9000/')
    parser.add_argument('--path', default='/tmp/blobs')
    parser.add_argument('--secret', default='secret')
    parser.add_argument('--uuid', default='user')
    parser.add_argument('--token', default=None)
    parser.add_argument('--cert-file', default='')

    subparsers = parser.add_subparsers(help='sub-command help', dest='action')

    # parse upload command
    parser_upload = subparsers.add_parser(
        'upload', help='upload blob and bypass local db')
    parser_upload.add_argument('payload')
    parser_upload.add_argument('blob_id')

    # parse download command
    parser_download = subparsers.add_parser(
        'download', help='download blob and bypass local db')
    parser_download.add_argument('blob_id')
    parser_download.add_argument('--output-file', default='/tmp/incoming-file')

    # parse put command
    parser_put = subparsers.add_parser(
        'put', help='put blob in local db and upload')
    parser_put.add_argument('payload')
    parser_put.add_argument('blob_id')

    # parse get command
    parser_get = subparsers.add_parser(
        'get', help='get blob from local db, get if needed')
    parser_get.add_argument('blob_id')

    # parse delete command
    parser_get = subparsers.add_parser(
        'delete', help='delete blob from local and remote db')
    parser_get.add_argument('blob_id')

    # parse list command
    parser_get = subparsers.add_parser(
        'list', help='list local and remote blob ids')

    # parse send_missing command
    parser_get = subparsers.add_parser(
        'send_missing', help='send all pending upload blobs')

    # parse send_missing command
    parser_get = subparsers.add_parser(
        'fetch_missing', help='fetch all new server blobs')

    # parse arguments
    args = parser.parse_args()

    # TODO convert these into proper unittests

    def _manager():
        mkdir_p(os.path.dirname(args.path))
        manager = BlobManager(
            args.path, args.url,
            'A' * 32, args.secret,
            args.uuid, args.token, args.cert_file)
        return manager

    @defer.inlineCallbacks
    def _upload(blob_id, payload):
        logger.info(":: Starting upload only: %s" % str((blob_id, payload)))
        manager = _manager()
        with open(payload, 'r') as fd:
            yield manager._encrypt_and_upload(blob_id, fd)
        logger.info(":: Finished upload only: %s" % str((blob_id, payload)))

    @defer.inlineCallbacks
    def _download(blob_id):
        logger.info(":: Starting download only: %s" % blob_id)
        manager = _manager()
        result = yield manager._download_and_decrypt(blob_id)
        logger.info(":: Result of download: %s" % str(result))
        if result:
            fd, _ = result
            with open(args.output_file, 'w') as f:
                logger.info(":: Writing data to %s" % args.output_file)
                f.write(fd.read())
        logger.info(":: Finished download only: %s" % blob_id)

    @defer.inlineCallbacks
    def _put(blob_id, payload):
        logger.info(":: Starting full put: %s" % blob_id)
        manager = _manager()
        size = os.path.getsize(payload)
        with open(payload) as fd:
            doc = BlobDoc(fd, blob_id)
            result = yield manager.put(doc, size=size)
        logger.info(":: Result of put: %s" % str(result))
        logger.info(":: Finished full put: %s" % blob_id)

    @defer.inlineCallbacks
    def _get(blob_id):
        logger.info(":: Starting full get: %s" % blob_id)
        manager = _manager()
        fd = yield manager.get(blob_id)
        if fd:
            logger.info(":: Result of get: " + fd.getvalue())
        logger.info(":: Finished full get: %s" % blob_id)

    @defer.inlineCallbacks
    def _delete(blob_id):
        logger.info(":: Starting deletion of: %s" % blob_id)
        manager = _manager()
        yield manager.delete(blob_id)
        logger.info(":: Finished deletion of: %s" % blob_id)

    @defer.inlineCallbacks
    def _list():
        logger.info(":: Listing local blobs")
        manager = _manager()
        local_list = yield manager.local_list()
        logger.info(":: Local list: %s" % local_list)
        logger.info(":: Listing remote blobs")
        remote_list = yield manager.remote_list()
        logger.info(":: Remote list: %s" % remote_list)

    @defer.inlineCallbacks
    def _send_missing():
        logger.info(":: Sending local pending upload docs")
        manager = _manager()
        yield manager.send_missing()
        logger.info(":: Finished sending missing docs")

    @defer.inlineCallbacks
    def _fetch_missing():
        logger.info(":: Fetching remote new docs")
        manager = _manager()
        yield manager.fetch_missing()
        logger.info(":: Finished fetching new docs")

    if args.action == 'upload':
        yield _upload(args.blob_id, args.payload)
    elif args.action == 'download':
        yield _download(args.blob_id)
    elif args.action == 'put':
        yield _put(args.blob_id, args.payload)
    elif args.action == 'get':
        yield _get(args.blob_id)
    elif args.action == 'delete':
        yield _delete(args.blob_id)
    elif args.action == 'list':
        yield _list()
    elif args.action == 'send_missing':
        yield _send_missing()
    elif args.action == 'fetch_missing':
        yield _fetch_missing()


if __name__ == '__main__':
    from twisted.internet.task import react
    react(testit)
