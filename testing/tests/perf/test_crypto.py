import pytest
import json
from uuid import uuid4
from leap.soledad.common.document import SoledadDocument
from leap.soledad.client.crypto import encrypt_sym
from leap.soledad.client.crypto import decrypt_sym


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

KEY = 'x'*32


def create_raw_encryption(size):
    @pytest.mark.benchmark(group="test_crypto_raw_encrypt")
    def test_raw_encrypt(benchmark):
        benchmark(encrypt_sym, 'x'*size, KEY)
    return test_raw_encrypt


def create_raw_decryption(size):
    @pytest.mark.benchmark(group="test_crypto_raw_decrypt")
    def test_raw_decrypt(benchmark):
        iv, ciphertext = encrypt_sym('x'*size, KEY)
        benchmark(decrypt_sym, ciphertext, KEY, iv)
    return test_raw_decrypt


test_encrypt_raw_10k = create_raw_encryption(10*1000)
test_encrypt_raw_100k = create_raw_encryption(100*1000)
test_encrypt_raw_500k = create_raw_encryption(500*1000)
test_encrypt_raw_1M = create_raw_encryption(1000*1000)
test_encrypt_raw_10M = create_raw_encryption(10*1000*1000)
test_encrypt_raw_50M = create_raw_encryption(50*1000*1000)
test_decrypt_raw_10k = create_raw_decryption(10*1000)
test_decrypt_raw_100k = create_raw_decryption(100*1000)
test_decrypt_raw_500k = create_raw_decryption(500*1000)
test_decrypt_raw_1M = create_raw_decryption(1000*1000)
test_decrypt_raw_10M = create_raw_decryption(10*1000*1000)
test_decrypt_raw_50M = create_raw_decryption(50*1000*1000)
