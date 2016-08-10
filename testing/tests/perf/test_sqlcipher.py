'''
Tests SoledadClient/SQLCipher interaction
'''
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


def build_test_sqlcipher_create(amount, size):
    @pytest.inlineCallbacks
    @pytest.mark.benchmark(group="test_sqlcipher_create")
    def test(soledad_client, txbenchmark):
        client = soledad_client()
        yield txbenchmark(load_up, client, amount, size)
    return test


test_create_20_500k = build_test_sqlcipher_create(20, 500*1000)
test_create_100_100k = build_test_sqlcipher_create(100, 100*1000)
test_create_1000_10k = build_test_sqlcipher_create(1000, 10*1000)
