import pytest
from io import BytesIO
from leap.soledad.server._blobs import FilesystemBlobsBackend
from twisted.internet import defer


def create_write_test(amount, size):

    @pytest.inlineCallbacks
    @pytest.mark.benchmark(group='test_blobs_fs_backend_write')
    def test(txbenchmark, payload, tmpdir):
        backend = FilesystemBlobsBackend(blobs_path=tmpdir.strpath)
        data = payload(size)
        deferreds = []
        for i in xrange(amount):
            fd = BytesIO(data)
            d = backend.write_blob('user', str(i), fd)
            deferreds.append(d)
        yield txbenchmark(defer.gatherResults, deferreds)

    return test


test_blobs_fs_backend_write_1_10000k = create_write_test(1, 10000 * 1000)
test_blobs_fs_backend_write_10_1000k = create_write_test(10, 1000 * 1000)
test_blobs_fs_backend_write_100_100k = create_write_test(100, 100 * 1000)
test_blobs_fs_backend_write_1000_10k = create_write_test(1000, 10 * 1000)


def create_read_test(amount, size):

    @pytest.inlineCallbacks
    @pytest.mark.benchmark(group='test_blobs_fs_backend_read')
    def test(txbenchmark, payload, tmpdir):
        backend = FilesystemBlobsBackend(blobs_path=tmpdir.strpath)
        data = payload(size)

        # first write blobs to the backend...
        deferreds = []
        for i in xrange(amount):
            fd = BytesIO(data)
            d = backend.write_blob('user', str(i), fd)
            deferreds.append(d)
        yield defer.gatherResults(deferreds)

        # ... then measure the read operation
        deferreds = []
        for i in xrange(amount):
            d = backend.read_blob('user', str(i))
            d.addCallback(lambda fd: fd.read())
            deferreds.append(d)
        yield txbenchmark(defer.gatherResults, deferreds)

    return test


test_blobs_fs_backend_read_1_10000k = create_read_test(1, 10000 * 1000)
test_blobs_fs_backend_read_10_1000k = create_read_test(10, 1000 * 1000)
test_blobs_fs_backend_read_100_100k = create_read_test(100, 100 * 1000)
test_blobs_fs_backend_read_1000_10k = create_read_test(1000, 10 * 1000)
