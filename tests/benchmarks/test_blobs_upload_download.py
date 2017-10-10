import base64
import pytest
import random
import sys
import uuid

from io import BytesIO

from twisted.internet.defer import gatherResults
from twisted.internet.defer import returnValue
from twisted.internet.defer import DeferredSemaphore

from leap.soledad.client._db.blobs import BlobDoc


def payload(size):
    random.seed(1337)  # same seed to avoid different bench results
    payload_bytes = bytearray(random.getrandbits(8) for _ in xrange(size))
    # encode as base64 to avoid ascii encode/decode errors
    return base64.b64encode(payload_bytes)[:size]  # remove b64 overhead


# used to limit the amount of concurrent accesses to the blob manager
semaphore = DeferredSemaphore(2)


def reclaim_free_space(client):
    return client.blobmanager.local.dbpool.runQuery("VACUUM")


#
# Download tests
#

@pytest.inlineCallbacks
def load_up_downloads(client, amount, data):
    # delete blobs from server
    ids = yield client.blobmanager.remote_list(namespace='payload')
    deferreds = []
    for blob_id in ids:
        d = semaphore.run(
            client.blobmanager.delete, blob_id, namespace='payload')
        deferreds.append(d)
    yield gatherResults(deferreds)

    # deliver some incoming blobs
    deferreds = []
    for i in xrange(amount):
        fd = BytesIO(data)
        doc = BlobDoc(fd, blob_id=uuid.uuid4().hex)
        size = sys.getsizeof(fd)
        d = semaphore.run(
            client.blobmanager.put, doc, size, namespace='payload')
        deferreds.append(d)
    yield gatherResults(deferreds)


@pytest.inlineCallbacks
def download_blobs(client, pending):
    deferreds = []
    for item in pending:
        d = semaphore.run(
            client.blobmanager.get, item, namespace='payload')
        deferreds.append(d)
    yield gatherResults(deferreds)


def create_blobs_download(amount, size):
    group = 'test_blobs_download_%d_%dk' % (amount, (size / 1000))

    @pytest.inlineCallbacks
    @pytest.mark.benchmark(group=group)
    def test(soledad_client, txbenchmark_with_setup):
        client = soledad_client()
        blob_payload = payload(size)

        yield load_up_downloads(client, amount, blob_payload)

        @pytest.inlineCallbacks
        def setup():
            yield client.blobmanager.local.dbpool.runQuery(
                "DELETE FROM blobs WHERE 1;")
            yield reclaim_free_space(client)
            returnValue(soledad_client(force_fresh_db=True))

        @pytest.inlineCallbacks
        def download(client):
            pending = yield client.blobmanager.remote_list(
                namespace='payload')
            yield download_blobs(client, pending)
            yield client.sync()

        yield txbenchmark_with_setup(setup, download)
    return test


# ATTENTION: update the documentation in ../docs/benchmarks.rst if you change
# the number of docs or the doc sizes for the tests below.
test_blobs_download_10_1000k = create_blobs_download(10, 1000 * 1000)
test_blobs_download_100_100k = create_blobs_download(100, 100 * 1000)
test_blobs_download_1000_10k = create_blobs_download(1000, 10 * 1000)


#
# Upload tests
#

@pytest.inlineCallbacks
def load_up_uploads(client, amount, data):
    # delete blobs from server
    ids = yield client.blobmanager.remote_list(namespace='payload')
    deferreds = []
    for blob_id in ids:
        d = semaphore.run(
            client.blobmanager.delete, blob_id, namespace='payload')
        deferreds.append(d)
    yield gatherResults(deferreds)


@pytest.inlineCallbacks
def upload_blobs(client, amount, data):
    deferreds = []
    for i in xrange(amount):
        fd = BytesIO(data)
        doc = BlobDoc(fd, blob_id=uuid.uuid4().hex)
        size = sys.getsizeof(fd)
        d = semaphore.run(
            client.blobmanager.put, doc, size, namespace='payload')
        deferreds.append(d)
    yield gatherResults(deferreds)


def create_blobs_upload(amount, size):
    group = 'test_blobs_upload_%d_%dk' % (amount, (size / 1000))

    @pytest.inlineCallbacks
    @pytest.mark.benchmark(group=group)
    def test(soledad_client, txbenchmark_with_setup):
        client = soledad_client()
        blob_payload = payload(size)

        @pytest.inlineCallbacks
        def setup():
            yield load_up_uploads(client, amount, blob_payload)
            returnValue(soledad_client(force_fresh_db=True))

        @pytest.inlineCallbacks
        def upload(client):
            yield upload_blobs(client, amount, blob_payload)
            yield client.sync()

        yield txbenchmark_with_setup(setup, upload)
    return test


# ATTENTION: update the documentation in ../docs/benchmarks.rst if you change
# the number of docs or the doc sizes for the tests below.
test_blobs_upload_10_1000k = create_blobs_upload(10, 1000 * 1000)
test_blobs_upload_100_100k = create_blobs_upload(100, 100 * 1000)
test_blobs_upload_1000_10k = create_blobs_upload(1000, 10 * 1000)
