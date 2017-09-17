'''
Tests SoledadClient/SQLCipher interaction
'''
import pytest

from twisted.internet.defer import gatherResults


def load_up(client, amount, payload, defer=True):
    results = [client.create_doc({'content': payload}) for _ in xrange(amount)]
    if defer:
        return gatherResults(results)


def build_test_sqlcipher_async_create(amount, size):
    @pytest.inlineCallbacks
    @pytest.mark.benchmark(group="test_sqlcipher_async_create")
    def test(soledad_client, txbenchmark_with_setup, payload):
        """
        Create many documents of a given size concurrently.
        """
        client = soledad_client()
        yield txbenchmark_with_setup(
            lambda: None, load_up, client, amount, payload(size))
    return test


def build_test_sqlcipher_create(amount, size):
    @pytest.mark.skip(reason="this test is lengthy and not a real use case")
    @pytest.mark.benchmark(group="test_sqlcipher_create")
    def test(soledad_client, monitored_benchmark, payload):
        """
        Create many documents of a given size serially.
        """
        client = soledad_client()._dbsyncer
        monitored_benchmark(
            load_up, client, amount, payload(size), defer=False)
    return test


test_async_create_10_1000k = build_test_sqlcipher_async_create(10, 1000 * 1000)
test_async_create_100_100k = build_test_sqlcipher_async_create(100, 100 * 1000)
test_async_create_1000_10k = build_test_sqlcipher_async_create(1000, 10 * 1000)
# synchronous
test_create_10_1000k = build_test_sqlcipher_create(10, 1000 * 1000)
test_create_100_100k = build_test_sqlcipher_create(100, 100 * 1000)
test_create_1000_10k = build_test_sqlcipher_create(1000, 10 * 1000)
