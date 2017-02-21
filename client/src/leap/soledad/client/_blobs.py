"""
Clientside BlobBackend Storage.
"""

from uuid import uuid4
import os.path

from io import BytesIO
from functools import partial

from sqlite3 import Binary

from twisted.logger import Logger
from twisted.enterprise import adbapi
from twisted.internet import defer, reactor

import treq

from leap.soledad.client.sqlcipher import SQLCipherOptions
from leap.soledad.client import pragmas

from _crypto import DocInfo, BlobEncryptor, BlobDecryptor


logger = Logger()


class _ConnectionPool(adbapi.ConnectionPool):

    def blob(self, table, column, key, value):
        conn = self.connectionFactory(self)
        # XXX FIXME what are these values???
        # shouldn't I pass the doc_id key?? Why is it asking for an integer???
        blob = conn.blob(table, column, 1, 1)
        print "GOT BLOB", blob
        return blob


"""
Ideally, the decrypting flow goes like this:

- GET a blob from remote server.
- Decrypt the preamble
- Allocate a zeroblob in the sqlcipher sink
- Mark the blob as unusable (ie, not verified)
- Decrypt the payload incrementally, and write chunks to sqlcipher
- Finalize the AES decryption
- If preamble + payload verifies correctly, mark the blob as usable

"""


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

    def __init__(self, local_path, remote, key, secret):
        self.local = SQLiteBlobBackend(local_path, key)
        self.remote = remote
        self.secret = secret

    @defer.inlineCallbacks
    def put(self, doc):
        fd = doc.blob_fd
        yield self.local.put(doc.blob_id, fd)
        fd.seek(0)
        up = BytesIO()
        doc_info = DocInfo(doc.doc_id, doc.rev)

        # TODO ------------------------------------------
        # this is wrong, is doing 2 stages.
        # the crypto producer can be passed to 
        # the uploader and react as data is written.
        # ------------------------------------------------
        yield self._encrypt(doc_info, fd, up)
        yield self._upload(doc.blob_id, up)

    @defer.inlineCallbacks
    def get(self, blob_id, doc_id, rev):
        local_blob = yield self.local.get(blob_id)
        if local_blob:
            print 'LOCAL BLOB', local_blob.getvalue()
            defer.returnValue(local_blob)

        print "NO LOCAL BLOB, WILL DOWNLOAD"

        blob, size = yield self._download_and_decrypt(blob_id, doc_id, rev)
        print "Downloading", blob_id
        print "BLOB", blob.getvalue(), "SIZE", size

        doc_info = DocInfo(doc_id, rev)
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
    def _encrypt(self, doc_info, payload, result):
        # TODO pass armor=False when the decrypter is bug-free
        crypter = BlobEncryptor(doc_info, payload, result=result, secret=self.secret)
        yield crypter.encrypt()


    @defer.inlineCallbacks
    def _upload(self, blob_id, payload_fd):
        uri = self.remote + 'put'
        yield treq.post(uri, data={'dafile_filename': blob_id},
                        files={'dafile': payload_fd})

    @defer.inlineCallbacks
    def _download_and_decrypt(self, blob_id, doc_id, rev):
        uri = self.remote + blob_id
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

        self.dbpool = dbpool = _ConnectionPool(
            backend, self.path, check_same_thread=False, timeout=5,
            cp_openfun=openfun, cp_min=1, cp_max=2, cp_name='blob_pool')

    @defer.inlineCallbacks
    def put(self, blob_id, blob_fd, size=None):
        insert = str('INSERT INTO blobs VALUES (?, zeroblob(?))')
        yield self.dbpool.runQuery(insert, (blob_id, size))
        cleartext = blob_fd.read()
        # FIXME --- I don't totally understand the parameters that are passed
        # to that call
        blob = self.dbpool.blob('blobs', 'payload', 'blob_id', blob_id)
        # TODO pass blob.write to a FileBodyProducer!!!
        # should be as simple as:
        # producer = BodyProducer(fd)
        # producer.startproducing(blob)
        blob.write(cleartext)

    @defer.inlineCallbacks
    def get(self, blob_id):
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
class BlobDoc(object):

    # TODO probably not needed, but convenient for testing for now.

    def __init__(self, doc_id, rev, content, blob_id=None):

        self.doc_id = doc_id
        self.rev = rev
        self.is_blob = True
        self.blob_fd = content
        if blob_id is None:
            blob_id = uuid4().get_hex()
        self.blob_id = blob_id
# --------------------8<----------------------------------------------

