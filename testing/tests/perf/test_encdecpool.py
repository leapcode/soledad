import pytest
import json
from uuid import uuid4
from twisted.internet.defer import gatherResults
from leap.soledad.client.encdecpool import SyncEncrypterPool
from leap.soledad.client.encdecpool import SyncDecrypterPool
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


def create_decrypt(amount, size):
    @pytest.mark.benchmark(group="test_pool_decrypt")
    @pytest.inlineCallbacks
    def test(soledad_client, txbenchmark_with_setup, request, payload):
        DOC_CONTENT = {'payload': payload(size)}
        client = soledad_client()

        def setup():
            pool = SyncDecrypterPool(
                client._crypto,
                client._sync_db,
                source_replica_uid=client._dbpool.replica_uid,
                insert_doc_cb=lambda x, y, z: False)  # ignored
            pool.start(amount)
            request.addfinalizer(pool.stop)
            crypto = client._crypto
            docs = []
            for _ in xrange(amount):
                doc = SoledadDocument(
                    doc_id=uuid4().hex, rev='rev',
                    json=json.dumps(DOC_CONTENT))
                encrypted_content = json.loads(crypto.encrypt_doc(doc))
                docs.append((doc.doc_id, encrypted_content))
            return pool, docs

        def put_and_wait(pool, docs):
            deferreds = []  # fires on completion
            for idx, (doc_id, content) in enumerate(docs, 1):
                deferreds.append(pool.insert_encrypted_received_doc(
                    doc_id, 'rev', content, idx, "trans_id", idx))
            return gatherResults(deferreds)

        yield txbenchmark_with_setup(setup, put_and_wait)
    return test

test_encdecpool_decrypt_100_10k = create_decrypt(100, 10*1000)
test_encdecpool_decrypt_100_100k = create_decrypt(100, 100*1000)
test_encdecpool_decrypt_100_500k = create_decrypt(100, 500*1000)
