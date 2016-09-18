import pytest
import json
from uuid import uuid4
from twisted.internet.defer import gatherResults
from leap.soledad.client.encdecpool import SyncEncrypterPool
from leap.soledad.common.document import SoledadDocument
# FIXME: test load is low due issue #7370, higher values will get out of memory


def create_encrypt(amount, size):
    @pytest.mark.benchmark(group="test_pool_encrypt")
    @pytest.inlineCallbacks
    def test(soledad_client, txbenchmark_with_setup, request, payload):
        DOC_CONTENT = {'payload': payload(size)}

        def setup():
            client = soledad_client()
            pool = SyncEncrypterPool(client._crypto, client._sync_db)
            pool.start()
            request.addfinalizer(pool.stop)
            docs = [
                SoledadDocument(doc_id=uuid4().hex, rev='rev',
                                json=json.dumps(DOC_CONTENT))
                for _ in xrange(amount)
            ]
            return pool, docs

        @pytest.inlineCallbacks
        def put_and_wait(pool, docs):
            yield gatherResults([pool.encrypt_doc(doc) for doc in docs])

        yield txbenchmark_with_setup(setup, put_and_wait)
    return test

test_encdecpool_encrypt_100_10k = create_encrypt(100, 10*1000)
test_encdecpool_encrypt_100_100k = create_encrypt(100, 100*1000)
test_encdecpool_encrypt_100_500k = create_encrypt(100, 500*1000)
