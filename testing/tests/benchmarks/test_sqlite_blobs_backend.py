import pytest
import os

from uuid import uuid4
from io import BytesIO

from twisted.internet.defer import gatherResults
from twisted.internet.defer import DeferredSemaphore

from leap.soledad.client._db.blobs import SQLiteBlobBackend


semaphore = DeferredSemaphore(2)


#
# put
#

def put(backend, amount, data):
    deferreds = []
    for _ in xrange(amount):
        blob_id = uuid4().hex
        fd = BytesIO(data)
        size = len(data)
        d = semaphore.run(backend.put, blob_id, fd, size)
        deferreds.append(d)
    return gatherResults(deferreds)


def create_put_test(amount, size):

    @pytest.inlineCallbacks
    @pytest.mark.sqlite_blobs_backend_put
    def test(txbenchmark, payload, tmpdir):
        dbpath = os.path.join(tmpdir.strpath, 'blobs.db')
        backend = SQLiteBlobBackend(dbpath, key='123')
        data = payload(size)
        yield txbenchmark(put, backend, amount, data)

    return test


test_sqlite_blobs_backend_put_1_10000k = create_put_test(1, 10000 * 1000)
test_sqlite_blobs_backend_put_10_1000k = create_put_test(10, 1000 * 1000)
test_sqlite_blobs_backend_put_100_100k = create_put_test(100, 100 * 1000)
test_sqlite_blobs_backend_put_1000_10k = create_put_test(1000, 10 * 1000)


#
# put
#

@pytest.inlineCallbacks
def get(backend):
    local = yield backend.list()
    deferreds = []
    for blob_id in local:
        d = backend.get(blob_id)
        deferreds.append(d)
    yield gatherResults(deferreds)


def create_get_test(amount, size):

    @pytest.inlineCallbacks
    @pytest.mark.sqlite_blobs_backend_get
    def test(txbenchmark, payload, tmpdir):
        dbpath = os.path.join(tmpdir.strpath, 'blobs.db')
        backend = SQLiteBlobBackend(dbpath, key='123')
        data = payload(size)

        yield put(backend, amount, data)
        yield txbenchmark(get, backend)

    return test


test_sqlite_blobs_backend_get_1_10000k = create_get_test(1, 10000 * 1000)
test_sqlite_blobs_backend_get_10_1000k = create_get_test(10, 1000 * 1000)
test_sqlite_blobs_backend_get_100_100k = create_get_test(100, 100 * 1000)
test_sqlite_blobs_backend_get_1000_10k = create_get_test(1000, 10 * 1000)
