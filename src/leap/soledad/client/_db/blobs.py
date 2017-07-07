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
import base64

from io import BytesIO
from functools import partial

from twisted.logger import Logger
from twisted.enterprise import adbapi
from twisted.internet import defer
from twisted.web.client import FileBodyProducer

import treq

from leap.soledad.common.errors import SoledadError
from leap.common.files import mkdir_p

from .._document import BlobDoc
from .._crypto import DocInfo
from .._crypto import BlobEncryptor
from .._crypto import BlobDecryptor
from .._http import HTTPClient
from .._pipes import TruncatedTailPipe
from .._pipes import PreamblePipe

from . import pragmas
from . import sqlcipher


logger = Logger()
FIXED_REV = 'ImmutableRevision'  # Blob content is immutable


class BlobAlreadyExistsError(SoledadError):
    pass


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

    def _blob(self, trans, table, column, irow, flags):
        # TODO: should not use transaction private variable here
        handle = trans._connection.blob(table, column, irow, flags)
        return handle


def check_http_status(code):
    if code == 409:
        raise BlobAlreadyExistsError()
    elif code != 200:
        raise SoledadError("Server Error")


class DecrypterBuffer(object):

    def __init__(self, blob_id, secret, tag):
        self.doc_info = DocInfo(blob_id, FIXED_REV)
        self.secret = secret
        self.tag = tag
        self.preamble_pipe = PreamblePipe(self._make_decryptor)

    def _make_decryptor(self, preamble):
        self.decrypter = BlobDecryptor(
            self.doc_info, preamble,
            secret=self.secret,
            armor=False,
            start_stream=False,
            tag=self.tag)
        return TruncatedTailPipe(self.decrypter, tail_size=len(self.tag))

    def write(self, data):
        self.preamble_pipe.write(data)

    def close(self):
        real_size = self.decrypter.decrypted_content_size
        return self.decrypter._end_stream(), real_size


class BlobManager(object):
    """
    Ideally, the decrypting flow goes like this:

    - GET a blob from remote server.
    - Decrypt the preamble
    - Allocate a zeroblob in the sqlcipher sink
    - Mark the blob as unusable (ie, not verified)
    - Decrypt the payload incrementally, and write chunks to sqlcipher
      ** Is it possible to use a small buffer for the aes writer w/o
      ** allocating all the memory in openssl?
    - Finalize the AES decryption
    - If preamble + payload verifies correctly, mark the blob as usable

    """

    def __init__(
            self, local_path, remote, key, secret, user, token=None,
            cert_file=None):
        if local_path:
            mkdir_p(os.path.dirname(local_path))
            self.local = SQLiteBlobBackend(local_path, key)
        self.remote = remote
        self.secret = secret
        self.user = user
        self._client = HTTPClient(user, token, cert_file)

    def close(self):
        if hasattr(self, 'local') and self.local:
            return self.local.close()

    @defer.inlineCallbacks
    def remote_list(self, **params):
        uri = urljoin(self.remote, self.user + '/')
        data = yield self._client.get(uri, params=params)
        defer.returnValue((yield data.json()))

    def local_list(self):
        return self.local.list()

    @defer.inlineCallbacks
    def send_missing(self):
        our_blobs = yield self.local_list()
        server_blobs = yield self.remote_list()
        missing = [b_id for b_id in our_blobs if b_id not in server_blobs]
        logger.info("Amount of documents missing on server: %s" % len(missing))
        # TODO: Send concurrently when we are able to stream directly from db
        for blob_id in missing:
            fd = yield self.local.get(blob_id)
            logger.info("Upload local blob: %s" % blob_id)
            yield self._encrypt_and_upload(blob_id, fd)

    @defer.inlineCallbacks
    def fetch_missing(self):
        # TODO: Use something to prioritize user requests over general new docs
        our_blobs = yield self.local_list()
        server_blobs = yield self.remote_list()
        docs_we_want = [b_id for b_id in server_blobs if b_id not in our_blobs]
        logger.info("Fetching new docs from server: %s" % len(docs_we_want))
        # TODO: Fetch concurrently when we are able to stream directly into db
        for blob_id in docs_we_want:
            logger.info("Fetching new doc: %s" % blob_id)
            yield self.get(blob_id)

    @defer.inlineCallbacks
    def put(self, doc, size):
        if (yield self.local.exists(doc.blob_id)):
            error_message = "Blob already exists: %s" % doc.blob_id
            raise BlobAlreadyExistsError(error_message)
        fd = doc.blob_fd
        # TODO this is a tee really, but ok... could do db and upload
        # concurrently. not sure if we'd gain something.
        yield self.local.put(doc.blob_id, fd, size=size)
        # In fact, some kind of pipe is needed here, where each write on db
        # handle gets forwarded into a write on the connection handle
        fd = yield self.local.get(doc.blob_id)
        yield self._encrypt_and_upload(doc.blob_id, fd)

    @defer.inlineCallbacks
    def get(self, blob_id):
        local_blob = yield self.local.get(blob_id)
        if local_blob:
            logger.info("Found blob in local database: %s" % blob_id)
            defer.returnValue(local_blob)

        result = yield self._download_and_decrypt(blob_id)

        if not result:
            defer.returnValue(None)
        blob, size = result

        if blob:
            logger.info("Got decrypted blob of type: %s" % type(blob))
            blob.seek(0)
            yield self.local.put(blob_id, blob, size=size)
            defer.returnValue((yield self.local.get(blob_id)))
        else:
            # XXX we shouldn't get here, but we will...
            # lots of ugly error handling possible:
            # 1. retry, might be network error
            # 2. try later, maybe didn't finished streaming
            # 3.. resignation, might be error while verifying
            logger.error('sorry, dunno what happened')

    @defer.inlineCallbacks
    def _encrypt_and_upload(self, blob_id, fd, **params):
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
        response = yield self._client.put(uri, data=fd, params=params)
        check_http_status(response.code)
        logger.info("Finished upload: %s" % (blob_id,))

    @defer.inlineCallbacks
    def _download_and_decrypt(self, blob_id):
        logger.info("Staring download of blob: %s" % blob_id)
        # TODO this needs to be connected in a tube
        uri = urljoin(self.remote, self.user + '/' + blob_id)
        data = yield self._client.get(uri)

        if data.code == 404:
            logger.warn("Blob not found in server: %s" % blob_id)
            defer.returnValue(None)
        elif not data.headers.hasHeader('Tag'):
            logger.error("Server didn't send a tag header for: %s" % blob_id)
            defer.returnValue(None)
        tag = data.headers.getRawHeaders('Tag')[0]
        tag = base64.urlsafe_b64decode(tag)
        buf = DecrypterBuffer(blob_id, self.secret, tag)

        # incrementally collect the body of the response
        yield treq.collect(data, buf.write)
        fd, size = buf.close()
        logger.info("Finished download: (%s, %d)" % (blob_id, size))
        defer.returnValue((fd, size))

    @defer.inlineCallbacks
    def delete(self, blob_id):
        logger.info("Staring deletion of blob: %s" % blob_id)
        yield self._delete_from_remote(blob_id)
        if (yield self.local.exists(blob_id)):
            yield self.local.delete(blob_id)

    def _delete_from_remote(self, blob_id):
        # TODO this needs to be connected in a tube
        uri = urljoin(self.remote, self.user + '/' + blob_id)
        return self._client.delete(uri)


class SQLiteBlobBackend(object):

    def __init__(self, path, key=None):
        self.path = os.path.abspath(
            os.path.join(path, 'soledad_blob.db'))
        mkdir_p(os.path.dirname(self.path))
        if not key:
            raise ValueError('key cannot be None')
        backend = 'pysqlcipher.dbapi2'
        opts = sqlcipher.SQLCipherOptions(
            '/tmp/ignored', binascii.b2a_hex(key),
            is_raw_key=True, create=True)
        pragmafun = partial(pragmas.set_init_pragmas, opts=opts)
        openfun = _sqlcipherInitFactory(pragmafun)

        self.dbpool = ConnectionPool(
            backend, self.path, check_same_thread=False, timeout=5,
            cp_openfun=openfun, cp_min=1, cp_max=2, cp_name='blob_pool')

    def close(self):
        from twisted._threads import AlreadyQuit
        try:
            self.dbpool.close()
        except AlreadyQuit:
            pass

    @defer.inlineCallbacks
    def put(self, blob_id, blob_fd, size=None):
        logger.info("Saving blob in local database...")
        insert = 'INSERT INTO blobs (blob_id, payload) VALUES (?, zeroblob(?))'
        irow = yield self.dbpool.insertAndGetLastRowid(insert, (blob_id, size))
        handle = yield self.dbpool.blob('blobs', 'payload', irow, 1)
        blob_fd.seek(0)
        # XXX I have to copy the buffer here so that I'm able to
        # return a non-closed file to the caller (blobmanager.get)
        # FIXME should remove this duplication!
        # have a look at how treq does cope with closing the handle
        # for uploading a file
        producer = FileBodyProducer(blob_fd)
        done = yield producer.startProducing(handle)
        logger.info("Finished saving blob in local database.")
        defer.returnValue(done)

    @defer.inlineCallbacks
    def get(self, blob_id):
        # TODO we can also stream the blob value using sqlite
        # incremental interface for blobs - and just return the raw fd instead
        select = 'SELECT payload FROM blobs WHERE blob_id = ?'
        result = yield self.dbpool.runQuery(select, (blob_id,))
        if result:
            defer.returnValue(BytesIO(str(result[0][0])))

    @defer.inlineCallbacks
    def list(self):
        query = 'select blob_id from blobs'
        result = yield self.dbpool.runQuery(query)
        if result:
            defer.returnValue([b_id[0] for b_id in result])
        else:
            defer.returnValue([])

    @defer.inlineCallbacks
    def exists(self, blob_id):
        query = 'SELECT blob_id from blobs WHERE blob_id = ?'
        result = yield self.dbpool.runQuery(query, (blob_id,))
        defer.returnValue(bool(len(result)))

    def delete(self, blob_id):
        query = 'DELETE FROM blobs WHERE blob_id = ?'
        return self.dbpool.runQuery(query, (blob_id,))


def _init_blob_table(conn):
    maybe_create = (
        "CREATE TABLE IF NOT EXISTS "
        "blobs ("
        "blob_id PRIMARY KEY, "
        "payload BLOB)")
    conn.execute(maybe_create)


def _sqlcipherInitFactory(fun):
    def _initialize(conn):
        fun(conn)
        _init_blob_table(conn)
    return _initialize


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
