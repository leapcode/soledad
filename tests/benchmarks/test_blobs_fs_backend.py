import pytest
from io import BytesIO
from leap.soledad.server._blobs import FilesystemBlobsBackend
from twisted.internet import defer
from twisted.web.client import FileBodyProducer
from twisted.internet._producer_helpers import _PullToPush
from uuid import uuid4


def create_write_test(amount, size):

    @pytest.inlineCallbacks
    @pytest.mark.benchmark(group='test_blobs_fs_backend_write')
    def test(txbenchmark_with_setup, payload, tmpdir):
        """
        Write many blobs of the same size to the filesystem backend.
        """
        backend = FilesystemBlobsBackend(blobs_path=tmpdir.strpath)
        data = payload(size)

        @pytest.inlineCallbacks
        def setup():
            blobs = yield backend.list_blobs('user')
            deferreds = []
            for blob_id in blobs:
                d = backend.delete_blob('user', blob_id)
                deferreds.append(d)
            yield defer.gatherResults(deferreds)

        @pytest.inlineCallbacks
        def write():
            semaphore = defer.DeferredSemaphore(100)
            deferreds = []
            for i in xrange(amount):
                producer = FileBodyProducer(BytesIO(data))
                blob_id = uuid4().hex
                d = semaphore.run(
                    backend.write_blob, 'user', blob_id, producer)
                deferreds.append(d)
            yield defer.gatherResults(deferreds)

        yield txbenchmark_with_setup(setup, write)

    return test


test_blobs_fs_backend_write_10_10000k = create_write_test(10, 10000 * 1000)
test_blobs_fs_backend_write_100_1000k = create_write_test(100, 1000 * 1000)
test_blobs_fs_backend_write_1000_100k = create_write_test(1000, 100 * 1000)
test_blobs_fs_backend_write_10000_10k = create_write_test(10000, 10 * 1000)


class DevNull(object):

    def write(self, data):
        pass

    def registerProducer(self, producer, streaming):
        producer = _PullToPush(producer, self)
        producer.startStreaming()

    def unregisterProducer(self):
        pass

    def finish(self):
        pass


def create_read_test(amount, size):

    @pytest.inlineCallbacks
    @pytest.mark.benchmark(group='test_blobs_fs_backend_read')
    def test(txbenchmark, payload, tmpdir):
        """
        Read many blobs of the same size from the filesystem backend.
        """
        backend = FilesystemBlobsBackend(blobs_path=tmpdir.strpath)
        data = payload(size)

        # first write blobs to the backend...
        semaphore = defer.DeferredSemaphore(100)
        deferreds = []
        for i in xrange(amount):
            producer = FileBodyProducer(BytesIO(data))
            d = semaphore.run(backend.write_blob, 'user', str(i), producer)
            deferreds.append(d)
        yield defer.gatherResults(deferreds)

        # ... then measure the read operation
        @pytest.inlineCallbacks
        def read():
            deferreds = []
            for i in xrange(amount):
                consumer = DevNull()
                d = semaphore.run(backend.read_blob, 'user', str(i), consumer)
                deferreds.append(d)
            yield defer.gatherResults(deferreds)

        yield txbenchmark(read)

    return test


test_blobs_fs_backend_read_10_10000k = create_read_test(10, 10000 * 1000)
test_blobs_fs_backend_read_100_1000k = create_read_test(100, 1000 * 1000)
test_blobs_fs_backend_read_1000_100k = create_read_test(1000, 100 * 1000)
test_blobs_fs_backend_read_10000_10k = create_read_test(10000, 10 * 1000)
