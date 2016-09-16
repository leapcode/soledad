import pytest

from twisted.internet.defer import gatherResults


def load_up(client, amount, payload):
    deferreds = []
    # create a bunch of local documents
    for i in xrange(amount):
        d = client.create_doc({'content': payload})
        deferreds.append(d)
    d = gatherResults(deferreds)
    d.addCallback(lambda _: None)
    return d


def create_upload(uploads, size):
    @pytest.inlineCallbacks
    @pytest.mark.benchmark(group="test_upload")
    def test(soledad_client, txbenchmark_with_setup, payload):
        client = soledad_client()

        def setup():
            return load_up(client, uploads, payload(size))

        yield txbenchmark_with_setup(setup, client.sync,
                                     defer_decryption=False)
    return test


test_upload_20_500k = create_upload(20, 500*1000)
test_upload_100_100k = create_upload(100, 100*1000)
test_upload_1000_10k = create_upload(1000, 10*1000)


def create_download(downloads, size):
    @pytest.inlineCallbacks
    @pytest.mark.benchmark(group="test_download")
    def test(soledad_client, txbenchmark_with_setup, payload):
        client = soledad_client()

        yield load_up(client, downloads, payload(size))
        yield client.sync()
        # We could create them directly on couch, but sending them
        # ensures we are dealing with properly encrypted docs

        def setup():
            return soledad_client()

        def sync(clean_client):
            return clean_client.sync()
        yield txbenchmark_with_setup(setup, sync)
    return test


test_download_20_500k = create_download(20, 500*1000)
test_download_100_100k = create_download(100, 100*1000)
test_download_1000_10k = create_download(1000, 10*1000)


@pytest.inlineCallbacks
@pytest.mark.benchmark(group="test_nothing_to_sync")
def test_nothing_to_sync(soledad_client, txbenchmark_with_setup):
    def setup():
        return soledad_client()

    def sync(clean_client):
        return clean_client.sync()
    yield txbenchmark_with_setup(setup, sync)
