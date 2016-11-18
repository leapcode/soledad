"""
Benchmarks for crypto operations.
If you don't want to stress your local machine too much, you can pass the
SIZE_LIMT environment variable.

For instance, to keep the maximum payload at 1MB:

SIZE_LIMIT=1E6 py.test -s tests/perf/test_crypto.py
"""
import pytest
import os
import json
from uuid import uuid4

from leap.soledad.common.document import SoledadDocument
from leap.soledad.client import _crypto

LIMIT = int(float(os.environ.get('SIZE_LIMIT', 50 * 1000 * 1000)))


pytestmark = pytest.mark.perf


def create_doc_encryption(size):
    @pytest.mark.benchmark(group="test_crypto_encrypt_doc")
    def test_doc_encryption(soledad_client, benchmark, payload):
        crypto = soledad_client()._crypto

        DOC_CONTENT = {'payload': payload(size)}
        doc = SoledadDocument(
            doc_id=uuid4().hex, rev='rev',
            json=json.dumps(DOC_CONTENT))

        benchmark(crypto.encrypt_doc, doc)
    return test_doc_encryption


# TODO this test is really bullshit, because it's still including
# the json serialization.

def create_doc_decryption(size):
    @pytest.inlineCallbacks
    @pytest.mark.benchmark(group="test_crypto_decrypt_doc")
    def test_doc_decryption(soledad_client, benchmark, payload):
        crypto = soledad_client()._crypto

        DOC_CONTENT = {'payload': payload(size)}
        doc = SoledadDocument(
            doc_id=uuid4().hex, rev='rev',
            json=json.dumps(DOC_CONTENT))

        encrypted_doc = yield crypto.encrypt_doc(doc)
        doc.set_json(encrypted_doc)

        benchmark(crypto.decrypt_doc, doc)
    return test_doc_decryption


def create_raw_encryption(size):
    @pytest.mark.benchmark(group="test_crypto_raw_encrypt")
    def test_raw_encrypt(benchmark, payload):
        key = payload(32)
        benchmark(_crypto.encrypt_sym, payload(size), key)
    return test_raw_encrypt


def create_raw_decryption(size):
    @pytest.mark.benchmark(group="test_crypto_raw_decrypt")
    def test_raw_decrypt(benchmark, payload):
        key = payload(32)
        iv, ciphertext = _crypto.encrypt_sym(payload(size), key)
        benchmark(_crypto.decrypt_sym, ciphertext, key, iv)
    return test_raw_decrypt


# Create the TESTS in the global namespace, they'll be picked by the benchmark
# plugin.

encryption_tests = [
    ('10k', 1E4),
    ('100k', 1E5),
    ('500k', 5E5),
    ('1M', 1E6),
    ('10M', 1E7),
    ('50M', 5E7),
]

for name, size in encryption_tests:
    if size < LIMIT:
        sz = int(size)
        globals()['test_encrypt_doc_' + name] = create_doc_encryption(sz)
        globals()['test_decrypt_doc_' + name] = create_doc_decryption(sz)


for name, size in encryption_tests:
    if size < LIMIT:
        sz = int(size)
        globals()['test_encrypt_raw_' + name] = create_raw_encryption(sz)
        globals()['test_decrypt_raw_' + name] = create_raw_decryption(sz)
