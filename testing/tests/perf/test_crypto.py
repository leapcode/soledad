import pytest
import json
from uuid import uuid4
from leap.soledad.common.document import SoledadDocument


def create_doc_encryption(size):
    @pytest.mark.benchmark(group="test_crypto_encrypt_doc")
    def test_doc_encryption(soledad_client, benchmark):
        crypto = soledad_client()._crypto

        DOC_CONTENT = {'payload': 'x'*size}
        doc = SoledadDocument(
            doc_id=uuid4().hex, rev='rev',
            json=json.dumps(DOC_CONTENT))

        benchmark(crypto.encrypt_doc, doc)
    return test_doc_encryption


def create_doc_decryption(size):
    @pytest.mark.benchmark(group="test_crypto_decrypt_doc")
    def test_doc_decryption(soledad_client, benchmark):
        crypto = soledad_client()._crypto

        DOC_CONTENT = {'payload': 'x'*size}
        doc = SoledadDocument(
            doc_id=uuid4().hex, rev='rev',
            json=json.dumps(DOC_CONTENT))
        encrypted_doc = crypto.encrypt_doc(doc)
        doc.set_json(encrypted_doc)

        benchmark(crypto.decrypt_doc, doc)
    return test_doc_decryption


test_encrypt_doc_10k = create_doc_encryption(10*1000)
test_encrypt_doc_100k = create_doc_encryption(100*1000)
test_encrypt_doc_500k = create_doc_encryption(500*1000)
test_encrypt_doc_1M = create_doc_encryption(1000*1000)
test_encrypt_doc_10M = create_doc_encryption(10*1000*1000)
test_encrypt_doc_50M = create_doc_encryption(50*1000*1000)
test_decrypt_doc_10k = create_doc_decryption(10*1000)
test_decrypt_doc_100k = create_doc_decryption(100*1000)
test_decrypt_doc_500k = create_doc_decryption(500*1000)
test_decrypt_doc_1M = create_doc_decryption(1000*1000)
test_decrypt_doc_10M = create_doc_decryption(10*1000*1000)
test_decrypt_doc_50M = create_doc_decryption(50*1000*1000)
