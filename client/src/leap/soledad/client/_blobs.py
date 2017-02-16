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

from _crypto import docinfo, BlobEncryptor, BlobDecryptor


logger = Logger()


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
        doc_info = docinfo(doc.doc_id, doc.rev)

        # TODO ------------------------------------------
        # this is wrong, is doing 2 stages. Cutting corners!
        # We should connect the pipeline, use Tubes: 
        # the crypto producer can be passed to 
        # the uploader and react as data is written.
        # ------------------------------------------------
        yield self._encrypt(doc_info, fd, up)
        yield self._upload(doc.blob_id, up)

    @defer.inlineCallbacks
    def get(self, blob_id, doc_id, rev):
        print "IN MANAGER: GETTING BLOB..."
        local_blob = yield self.local.get(blob_id)
        if local_blob:
            print 'LOCAL BLOB', local_blob
            defer.returnValue(local_blob)

        print "NO LOCAL BLOB, WILL DOWNLOAD"

        # TODO pass the fd to the downloader, possible?
        remoteblob = yield self._download(blob_id)
        ciphertext = BytesIO(str(remoteblob))

        print 'remote ciphertext', remoteblob[:10], '[...]'
        logger.debug('got remote blob %s [...]' % remoteblob[:100])
        del remoteblob

        doc_info = docinfo(doc_id, rev)
        blob = yield self._decrypt(doc_info, ciphertext)
        if blob:
            print 'GOT DECRYPTED BLOB', type(blob)
            blob.seek(0)
            print 'SAVING BLOB IN LOCAL STORE'
            yield self.local.put(blob_id, blob)
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
        # TODO WE SHOULD SKIP THE BASE64 STEP!!!!
        # this is going to be uploaded in binary mode
        crypter = BlobEncryptor(doc_info, payload, result=result, secret=self.secret)
        yield crypter.encrypt()


    @defer.inlineCallbacks
    def _decrypt(self, doc_info, ciphertext):
        decrypter = BlobDecryptor(doc_info, ciphertext, secret=self.secret)
        blob = yield decrypter.decrypt()
        defer.returnValue(blob)


    @defer.inlineCallbacks
    def _upload(self, blob_id, payload_fd):
        uri = self.remote + 'put'
        yield treq.post(uri, data={'dafile_filename': blob_id},
                        files={'dafile': payload_fd})

    @defer.inlineCallbacks
    def _download(self, blob_id):
        uri = self.remote + 'blobs/' + blob_id
        blob_resp = yield treq.get(uri)
        blob = yield treq.text_content(blob_resp)
        defer.returnValue(blob)



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

        self.dbpool = dbpool = adbapi.ConnectionPool(
            backend, self.path, check_same_thread=False, timeout=5,
            cp_openfun=openfun, cp_min=1, cp_max=2, cp_name='blob_pool')


    @defer.inlineCallbacks
    def put(self, blob_id, blob_fd):
        insert = str('INSERT INTO blobs VALUES (?, ?)')
        print 'inserting...'
        raw = blob_fd.getvalue()
        yield self.dbpool.runQuery(insert, (blob_id, Binary(raw)))
        
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
