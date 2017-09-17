import pytest

from twisted.internet import defer


@pytest.inlineCallbacks
def load_up(client, amount, payload):
    # create a bunch of local documents
    deferreds = []
    for i in xrange(amount):
        deferreds.append(client.create_doc({'content': payload}))
    yield defer.gatherResults(deferreds)


def create_upload(amount, size):

    @pytest.mark.responsiveness
    @pytest.inlineCallbacks
    def _test(soledad_client, payload, watchdog):

        client = soledad_client()
        yield load_up(client, amount, payload(size))
        yield watchdog(client.sync)

    return _test


test_responsiveness_upload_10_1000k = create_upload(10, 1000 * 1000)
test_responsiveness_upload_100_100k = create_upload(100, 100 * 1000)
test_responsiveness_upload_1000_10k = create_upload(1000, 10 * 1000)


def create_download(downloads, size):

    @pytest.mark.responsiveness
    @pytest.inlineCallbacks
    def _test(soledad_client, payload, watchdog):
        client = soledad_client()
        yield load_up(client, downloads, payload(size))
        yield client.sync()

        clean_client = soledad_client(force_fresh_db=True)
        yield watchdog(clean_client.sync)

    return _test


test_responsiveness_download_10_1000k = create_download(10, 1000 * 1000)
test_responsiveness_download_100_100k = create_download(100, 100 * 1000)
test_responsiveness_download_1000_10k = create_download(1000, 10 * 1000)
