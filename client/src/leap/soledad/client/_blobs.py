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

from copy import copy
import os.path

from io import BytesIO
from functools import partial


from twisted.logger import Logger
from twisted.enterprise import adbapi
from twisted.internet import defer
from twisted.web.client import FileBodyProducer

import treq

from leap.soledad.client.sqlcipher import SQLCipherOptions
from leap.soledad.client import pragmas

from _crypto import DocInfo, BlobEncryptor, BlobDecryptor


logger = Logger()


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


class DecrypterBuffer(object):

    def __init__(self, doc_id, rev, secret):
        self.decrypter = None
        self.buffer = BytesIO()
        self.doc_info = DocInfo(doc_id, rev)
        self.secret = secret
        self.d = None

    def write(self, data):
        if not self.decrypter:
            self.buffer.write(data)
            self.decrypter = BlobDecryptor(
                self.doc_info, self.buffer,
                secret=self.secret,
                armor=True,
                start_stream=False)
            self.d = self.decrypter.decrypt()
        else:
            self.decrypter.write(data)

    def close(self):
        if self.d:
            self.d.addCallback(lambda result: (result, self.decrypter.size))
        return self.d


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

    def __init__(self, local_path, remote, key, secret, user):
        self.local = SQLiteBlobBackend(local_path, key)
        self.remote = remote
        self.secret = secret
        self.user = user

    @defer.inlineCallbacks
    def put(self, doc):
        fd = doc.blob_fd
        # TODO this is a tee really, but ok... could do db and upload
        # concurrently. not sure if we'd gain something.
        yield self.local.put(doc.blob_id, fd)
        fd.seek(0)
        yield self._encrypt_and_upload(doc.blob_id, fd, up)

    @defer.inlineCallbacks
    def get(self, blob_id, doc_id, rev):
        local_blob = yield self.local.get(blob_id)
        if local_blob:
            print "GOT LOCAL BLOB", local_blob
            defer.returnValue(local_blob)

        blob, size = yield self._download_and_decrypt(blob_id, doc_id, rev)
        print "DOWNLOADED BLOB, SIZE:", size

        if blob:
            print 'GOT DECRYPTED BLOB', type(blob)
            print 'SAVING BLOB IN LOCAL STORE'
            blob.seek(0)
            yield self.local.put(blob_id, blob, size=size)
            blob.seek(0)
            defer.returnValue(blob)
        else:
            # XXX we shouldn't get here, but we will...
            # lots of ugly error handling possible:
            # 1. retry, might be network error
            # 2. try later, maybe didn't finished streaming
            # 3.. resignation, might be error while verifying
            logger.error('sorry, dunno what happened')

    @defer.inlineCallbacks
    def _encrypt_and_upload(self, blob_id, doc_id, rev, payload):
        # TODO ------------------------------------------
        # this is wrong, is doing 2 stages.
        # the crypto producer can be passed to
        # the uploader and react as data is written.
        # try to rewrite as a tube: pass the fd to aes and let aes writer
        # produce data to the treq request fd.
        # ------------------------------------------------
        doc_info = DocInfo(doc_id, rev)
        uri = self.remote + '/' + self.user + '/' + blob_id
        crypter = BlobEncryptor(doc_info, payload, secret=self.secret,
                                armor=True)
        result = yield crypter.encrypt()
        yield treq.put(uri, data=result)

    @defer.inlineCallbacks
    def _download_and_decrypt(self, blob_id, doc_id, rev):
        # TODO this needs to be connected in a tube
        uri = self.remote + self.user + '/' + blob_id
        buf = DecrypterBuffer(doc_id, rev, self.secret)
        data = yield treq.get(uri)
        yield treq.collect(data, buf.write)
        blob = yield buf.close()
        defer.returnValue(blob)


class SQLiteBlobBackend(object):

    def __init__(self, path, key=None):
        self.path = os.path.abspath(
            os.path.join(path, 'soledad_blob.db'))
        if not key:
            raise ValueError('key cannot be None')
        backend = 'pysqlcipher.dbapi2'
        opts = SQLCipherOptions('/tmp/ignored', key)
        pragmafun = partial(pragmas.set_init_pragmas, opts=opts)
        openfun = _sqlcipherInitFactory(pragmafun)

        self.dbpool = ConnectionPool(
            backend, self.path, check_same_thread=False, timeout=5,
            cp_openfun=openfun, cp_min=1, cp_max=2, cp_name='blob_pool')

    @defer.inlineCallbacks
    def put(self, blob_id, blob_fd, size=None):
        insert = 'INSERT INTO blobs (blob_id, payload) VALUES (?, zeroblob(?))'
        irow = yield self.dbpool.insertAndGetLastRowid(insert, (blob_id, size))
        handle = yield self.dbpool.blob('blobs', 'payload', irow, 1)
        blob_fd.seek(0)
        # XXX I have to copy the buffer here so that I'm able to
        # return a non-closed file to the caller (blobmanager.get)
        # FIXME should remove this duplication!
        # have a look at how treq does cope with closing the handle
        # for uploading a file
        producer = FileBodyProducer(copy(blob_fd))
        done = yield producer.startProducing(handle)
        defer.returnValue(done)

    @defer.inlineCallbacks
    def get(self, blob_id):
        # TODO we can also stream the blob value using sqlite
        # incremental interface for blobs - and just return the raw fd instead
        select = 'SELECT payload FROM blobs WHERE blob_id = ?'
        result = yield self.dbpool.runQuery(select, (blob_id,))
        if result:
            defer.returnValue(BytesIO(str(result[0][0])))


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


# --------------------8<----------------------------------------------
# class BlobDoc(object):
#
#     # TODO probably not needed, but convenient for testing for now.
#
#     def __init__(self, doc_id, rev, content, blob_id=None):
#
#         self.doc_id = doc_id
#         self.rev = rev
#         self.is_blob = True
#         self.blob_fd = content
#         if blob_id is None:
#             blob_id = uuid4().get_hex()
#         self.blob_id = blob_id
# --------------------8<----------------------------------------------


@defer.inlineCallbacks
def testit(reactor):

    # TODO convert this into proper unittests

    import sys
    try:
        cmd = sys.argv[1]
    except:
        cmd = ''

    if cmd == 'upload':
        src = sys.argv[2]
        blob_id = sys.argv[3]

        doc_info = DocInfo('mydoc', '1')
        print "DOC INFO", doc_info

        # I don't use BlobManager here because I need to avoid
        # putting the blob on local db on upload
        crypter = BlobEncryptor(
            doc_info, open(src, 'r'), 'A' * 32, armor=True)
        print "UPLOADING WITH ENCRYPTOR"
        result = yield crypter.encrypt()
        yield treq.put('http://localhost:9000/user/' + blob_id, data=result)

    elif cmd == 'download':
        blob_id = sys.argv[2]
        manager = BlobManager(
            '/tmp/blobs', 'http://localhost:9000/',
            'A' * 32, 'secret', 'user')
        result = yield manager.get(blob_id, 'mydoc', '1')
        print result.getvalue()

    else:
        print "Usage:"
        print "cd server/src/leap/soledad/server/ && python _blobs.py"
        print "python _blobs.py upload /path/to/file blob_id"
        print "python _blobs.py download blob_id"


if __name__ == '__main__':
    from twisted.internet.task import react
    react(testit)
