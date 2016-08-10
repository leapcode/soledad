import pytest

from twisted.internet.defer import gatherResults


def load_up(client, amount, size):
    content = 'x'*size
    deferreds = []
    # create a bunch of local documents
    for i in xrange(amount):
        d = client.create_doc({'content': content})
        deferreds.append(d)
    d = gatherResults(deferreds)
    d.addCallback(lambda _: None)
    return d


@pytest.inlineCallbacks
@pytest.mark.benchmark(group="test_upload")
def test_upload_20_500k(soledad_client, txbenchmark_with_setup):
    uploads, size, client = 20, 500*1000, soledad_client()

    def setup():
        return load_up(client, uploads, size)

    yield txbenchmark_with_setup(setup, client.sync)


@pytest.inlineCallbacks
@pytest.mark.benchmark(group="test_upload")
def test_upload_100_100k(soledad_client, txbenchmark_with_setup):
    uploads, size, client = 100, 100*1000, soledad_client()

    def setup():
        return load_up(client, uploads, size)

    yield txbenchmark_with_setup(setup, client.sync)


@pytest.inlineCallbacks
@pytest.mark.benchmark(group="test_upload")
def test_upload_1000_10k(soledad_client, txbenchmark_with_setup):
    uploads, size, client = 1000, 10*1000, soledad_client()

    def setup():
        return load_up(client, uploads, size)

    yield txbenchmark_with_setup(setup, client.sync)


@pytest.inlineCallbacks
@pytest.mark.benchmark(group="test_download")
def test_download_20_500k(soledad_client, txbenchmark_with_setup):
    downloads, size, client = 20, 500*1000, soledad_client()

    yield load_up(client, downloads, size)
    yield client.sync()

    def setup():
        clean_client = soledad_client()
        return (clean_client,), {}

    def sync(clean_client):
        return clean_client.sync()
    yield txbenchmark_with_setup(setup, sync)


@pytest.inlineCallbacks
@pytest.mark.benchmark(group="test_download")
def test_download_100_100k(soledad_client, txbenchmark_with_setup):
    downloads, size, client = 100, 100*1000, soledad_client()

    yield load_up(client, downloads, size)
    yield client.sync()
    # We could create them directly on remote db, but sending them
    # ensures we are dealing with properly encrypted docs

    def setup():
        clean_client = soledad_client()
        return (clean_client,), {}

    def sync(clean_client):
        return clean_client.sync()
    yield txbenchmark_with_setup(setup, sync)


@pytest.inlineCallbacks
@pytest.mark.benchmark(group="test_download")
def test_download_1000_10k(soledad_client, txbenchmark_with_setup):
    downloads, size, client = 1000, 10*1000, soledad_client()

    yield load_up(client, downloads, size)
    yield client.sync()

    def setup():
        clean_client = soledad_client()
        return (clean_client,), {}

    def sync(clean_client):
        return clean_client.sync()
    yield txbenchmark_with_setup(setup, sync)
