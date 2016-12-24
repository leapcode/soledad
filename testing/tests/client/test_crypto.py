# -*- coding: utf-8 -*-
# test_crypto.py
# Copyright (C) 2013 LEAP
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
"""
Tests for cryptographic related stuff.
"""
import binascii
import base64
import json
import os
import scrypt

from io import BytesIO

import pytest

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

from leap.soledad.common.document import SoledadDocument
from test_soledad.util import BaseSoledadTest
from leap.soledad.client import _crypto
from leap.soledad.client._secrets import SecretsCrypto

from twisted.trial import unittest
from twisted.internet import defer


snowden1 = (
    "You can't come up against "
    "the world's most powerful intelligence "
    "agencies and not accept the risk. "
    "If they want to get you, over time "
    "they will.")


class AESTest(unittest.TestCase):

    def test_chunked_encryption(self):
        key = 'A' * 32

        fd = BytesIO()
        aes = _crypto.AESWriter(key, _buffer=fd)
        iv = aes.iv

        data = snowden1
        block = 16

        for i in range(len(data) / block):
            chunk = data[i * block:(i + 1) * block]
            aes.write(chunk)
        aes.end()

        ciphertext_chunked = fd.getvalue()
        ciphertext, tag = _aes_encrypt(key, iv, data)

        assert ciphertext_chunked == ciphertext

    def test_decrypt(self):
        key = 'A' * 32
        iv = 'A' * 16

        data = snowden1
        block = 16

        ciphertext, tag = _aes_encrypt(key, iv, data)

        fd = BytesIO()
        aes = _crypto.AESWriter(key, iv, fd, tag=tag)

        for i in range(len(ciphertext) / block):
            chunk = ciphertext[i * block:(i + 1) * block]
            aes.write(chunk)
        aes.end()

        cleartext_chunked = fd.getvalue()
        assert cleartext_chunked == data


class BlobTestCase(unittest.TestCase):

    class doc_info:
        doc_id = 'D-deadbeef'
        rev = '397932e0c77f45fcb7c3732930e7e9b2:1'

    @defer.inlineCallbacks
    def test_blob_encryptor(self):

        inf = BytesIO(snowden1)

        blob = _crypto.BlobEncryptor(
            self.doc_info, inf,
            secret='A' * 96)

        encrypted = yield blob.encrypt()
        preamble, ciphertext = _crypto._split(encrypted.getvalue())
        ciphertext = ciphertext[:-16]

        assert len(preamble) == _crypto.PACMAN.size
        unpacked_data = _crypto.PACMAN.unpack(preamble)
        magic, sch, meth, ts, iv, doc_id, rev = unpacked_data
        assert magic == _crypto.BLOB_SIGNATURE_MAGIC
        assert sch == 1
        assert meth == _crypto.ENC_METHOD.aes_256_gcm
        assert iv == blob.iv
        assert doc_id == 'D-deadbeef'
        assert rev == self.doc_info.rev

        aes_key = _crypto._get_sym_key_for_doc(
            self.doc_info.doc_id, 'A' * 96)
        assert ciphertext == _aes_encrypt(aes_key, blob.iv, snowden1)[0]

        decrypted = _aes_decrypt(aes_key, blob.iv, blob.tag, ciphertext,
                                 preamble)
        assert str(decrypted) == snowden1

    @defer.inlineCallbacks
    def test_blob_decryptor(self):

        inf = BytesIO(snowden1)

        blob = _crypto.BlobEncryptor(
            self.doc_info, inf,
            secret='A' * 96)
        ciphertext = yield blob.encrypt()

        decryptor = _crypto.BlobDecryptor(
            self.doc_info, ciphertext,
            secret='A' * 96)
        decrypted = yield decryptor.decrypt()
        assert decrypted == snowden1

    @defer.inlineCallbacks
    def test_encrypt_and_decrypt(self):
        """
        Check that encrypting and decrypting gives same doc.
        """
        crypto = _crypto.SoledadCrypto('A' * 96)
        payload = {'key': 'someval'}
        doc1 = SoledadDocument('id1', '1', json.dumps(payload))

        encrypted = yield crypto.encrypt_doc(doc1)
        assert encrypted != payload
        assert 'raw' in encrypted
        doc2 = SoledadDocument('id1', '1')
        doc2.set_json(encrypted)
        assert _crypto.is_symmetrically_encrypted(encrypted)
        decrypted = yield crypto.decrypt_doc(doc2)
        assert len(decrypted) != 0
        assert json.loads(decrypted) == payload

    @defer.inlineCallbacks
    def test_decrypt_with_wrong_tag_raises(self):
        """
        Trying to decrypt a document with wrong MAC should raise.
        """
        crypto = _crypto.SoledadCrypto('A' * 96)
        payload = {'key': 'someval'}
        doc1 = SoledadDocument('id1', '1', json.dumps(payload))

        encrypted = yield crypto.encrypt_doc(doc1)
        encdict = json.loads(encrypted)
        preamble, raw = _crypto._split(str(encdict['raw']))
        # mess with tag
        messed = raw[:-16] + '0' * 16

        preamble = base64.urlsafe_b64encode(preamble)
        newraw = preamble + ' ' + base64.urlsafe_b64encode(str(messed))
        doc2 = SoledadDocument('id1', '1')
        doc2.set_json(json.dumps({"raw": str(newraw)}))

        with pytest.raises(_crypto.InvalidBlob):
            yield crypto.decrypt_doc(doc2)


class SecretsCryptoTestCase(unittest.TestCase):

    SECRETS = {
        'remote_secret': 'a' * 512,
        'local_salt': 'b' * 64,
        'local_secret': 'c' * 448
    }
    ENCRYPTED_V2 = {
        'cipher': 'aes_256_gcm',
        'length': 1437,
        'kdf_salt': 'TSgNLeAGFeITeSgNzmYZHh+mzmkZPOqao7CAV/tx3KZCLwsrT0HmWtVK3'
                    'TyWHWNgVdeamMZYRuvZavE2sp0DGw==\n',
        'iv': 'TKZQKIlRgdnXFhJf08qswg==',
        'secrets': 'ZNZRi72VDtwZqyuU+uf3yzZt23vCtMS3Ki2bnZyeHUOSGVweJeDadF4oqE'
                   'BW87NN00j9E49BzyzLr9SNgwZjPp0wlUm7kt+s8EUfJUdH8nxaQ+9iqGXM'
                   'cCHmBM8L8DRN2m3BrPGx7m+QGlN9sbrRpl7fqc46RWcYuTEpm4upjdtI7O'
                   'jDd0JG3C0rUzIuKJn9w4rEpX3tLEKXVdZfLvRXS5roR0cauazsDO69E13q'
                   'a01vDuY+UJ+buLQ3FluPnnk8QE7ztPVUmRJJ76yAIhjVX9owiwlp9GnUJY'
                   'sETRCqdRSTwUcHIkzVR0zAvtxTX7eGTitzf4gCYEC4T9v5N/jHxEfPdx28'
                   'MM4KShWN2nFxNFQLQUpMN2OrM7UyUw+DQ3ydqBeBPKPHRN5s05kIK7P/Ra'
                   'aLNcrJWa7DopLbgLlei0Jd7S4sjv1ufaRY7v0qJaVkhh/VaCylTSVw1rv5'
                   'YzSWcHHcLuC0R8xLadz6T+EpsVYxgPYCS7w5xoE82zwNQzw/EBxLIcyLPl'
                   'ipKnr2dttrmm3KXUOT1IdbSbI5elF6yQTAusdqiXuypey+MDqHYWEYWkCn'
                   'e9/uGM9FjklDLE0RtPEDxhq64tw6u2Xu7RzDzyQDI8EIoTdU+4zEMTnelZ'
                   'fKEwdG58EDxTXfUk6IDcRUupz3YuToSMhIOkqgXnbWl/nrK0O9v4JMhQjI'
                   'r+oPICYfFr14kvJXBsfntILTJCxzbqTQcNba3jc8rGqCZ6gM0u4PndwTG2'
                   'UiCqPU2HMnWvVGQOXeLdQY+EqqXQiRDi0DrDmkVwFf+27dPXxmZ43C48W3'
                   'lMhTKXl0rdBFnOD5jiMh0X6q/KYXonyEtMZMsjT7dFePcCy4wQRhuut+ac'
                   '/TJWyrr+/IB45E+LZbhV7xCy1dYsbdb52jTRJFpaQ83sj6Iv6SYdiqqXzL'
                   'F5JGMyuovTjwAoIIQzpLv36xY2wGGAH1V8c7QmDR2qumXrHD9R68WjBoSY'
                   '7IFM0TFAGZNun56y/zQ4r8yOMSAId+j4kuRH0fENEi0FJ+SpmSdHfpvBhE'
                   'MdGh927E9enEYWmUQMmkxXIw6E+O3cmOWt2hsMbUAikDCpQOnVP2BD55HT'
                   '6FfbW7ITVwPINHYexmy2Xcm8H5zzGFSp+uYIyPBYDKA+VJ+QQI8bud9K+T'
                   'NBybUv9u6LbB6BsLpwLoxMPJu0WsN2HpmLYgrg2ML1huMF1OtaGRuUr2PL'
                   'NBaZaL6VOztYrVtQG1+tNyRxn8XQTtx0l6n+EihGVe9Sk5XF6DJA9ZN7uO'
                   'svTUFJ5qG3Erf4AmbUJWoOR/NvapBtifidM7gPZZ6NqBs6v72rU1pGy+p7'
                   'o84KrmB2MNf3yJ0BvKxPvFmltF3Dc7LB5TN8ycbmFM6hgrLvvhPxiHEnG/'
                   '8Qcrg0nUXOipFGNgZEU7t7Mz6RJ189Z2Kx1HVGrkAzEgqwZYqijAPlsgzO'
                   'bg6DwzwC7stolQWGCDQUtJVlE8FZ/Up8zFYYZKn52WzjmSN4/hHhEvdkck'
                   'Nez/JVev6fMcVrgdrTZ+uCwxjN/4xPdgog2HV470ea1bvIkSNOOrhm194M'
                   '40GmvmBhiSSMjdRQCQtM0t9bUuSQLPDzEiCA9QaLyygtlz9uRR/dXgkEg0'
                   'J4YNpZvhE0wbyp4GHytbPaAmrcd7im9+buTuMwhXpZl0stmfkJxVHJSZ8Y'
                   'IHakHs3W1fdYyI3wxGpel/9eYO3ISukolwrHXESP65wVNKfBwbqVJzQmts'
                   'pyDBOI6DcLKZfE1EVg0+uwQ/5PKZbn0TwlXO1YE3NL3mAply3zQR9hyBrY'
                   '6f1jkHVD3irIlWkSiPJsP8sW+nrK8c/Ha8F+dua6DTZmg594OIaQj8mPiY'
                   'GcIusiARWocR5/MmSjupGOgFx4HtmckTJtAta3XP4elOx04teH/P9Cgr1x'
                   'XYf+cEX6gp92L9rTo0FCz3Hw==\n',
        'version': 2,
        'kdf': 'scrypt',
        'kdf_length': 32
    }

    ENCRYPTED_V1 = {
        'version': 1,
        'active_secret': 'secret_id',
        'storage_secrets': {
            'secret_id': {
                'kdf': 'scrypt',
                'secret': 'u31ObvxNU8jB0HgMj3TVwQ==:JQwlYq6sAQmHYS3x2CJzObT9h'
                          'j1iiHthvrMh887qedNCcOfJyCA3jpRkc0vjd2Qk/2HSJ+JxM2F'
                          'MrPzzx5O34EHlgF2scen34guZRRIf42WpnMy+PrL4cnMlZLgCh'
                          'H1Jz6wcIMEpU9LQ8OaCShk1/yJ6qcVHOV4DDt3mTF7ttiqI5cp'
                          'msaVtxxYCcpxFiWSeSCEgr0h4/Ih1qHuM6vk+CQjf/zg1f/7HR'
                          'imIyNYXit9Fw3YTkxBen1wG3f5L7OAODRTuqnWpkQFOmclx050'
                          'k0frKRcX6UWhIOWpW2mqJXnvzDtQQVGzqIdSgGTGtUDGQ7Onnc'
                          'NkUlSnuVC7PkDNNRuwit3pCB9YWBWyPAQgs0kLqoV4YcuSctz6'
                          'SAf76ozdcK5/SrOzutOfyPag4V3AYKMv6rCKALJ10OnFJ61FL9'
                          'kd6JZam7WOlEUXyO7Gdgvz+eKiQMTZXbtO2kAKqel513MedPXC'
                          'dzajUe1U2JaGg86UdiDWoPYOiWxnAPwfNJk+1QuNy5NZ7PaMtF'
                          'IKT3/Xema2U8mufS0FbvJyK2flP1VUWcCzHKTSqX6+kU7UpoWa'
                          'hYa7PlO40El+putTQLBmNaEeaWFngO+XB4TReICHSiCdcAb3pw'
                          'sabjtxt+OpK4vbj3yBSfpiZTpVbEjt9U/tUpVp/T2M66lMi3ZC'
                          'oHLlhu45Zo0aEq3UmQ/WBXu6EkO2eLYz2br9YQwRbSJ6z5CHmu'
                          'hjKBQlpvGNfZYObx5lY4o6Ab4f/N8gyukskjmAFAf7Fr8cEog/'
                          'oxmbagoCtUGRYJp2paooqH8L6xXp0Y8+23g7WJaAIr1i4V4aKS'
                          'r9x7iUK6prcZTtMJZEHCswkLN/+DU6/FX3YZcOjseC+Qv3P+9v'
                          'zIDp/92KJzqVqITGwrsc6ZsglMW37qxs6albtw3lMWSHlkcLbj'
                          'Xf/iHPeKnb2WNLdkFNQ1J5OaTJR+E1CrXN+pm1JtB6XaUbaLGV'
                          'CGUo13lAPVDtXcPbo64kMrQtQu4m9m8X8t8tfuJmINfwBnrKzk'
                          'O6pl+LwimFaFEArV6wcaMxmwi0lM7mt4U1u9OIQjghQ/dEmOyV'
                          'dZBnvyG7T/oRuLdUyZ/QGXZMlPQ3lAZ0ONn1Mk4bmKToW8ToE8'
                          'ylld3rLlWDjjoQP8mP05Izg3mguLHXUhikUL8MD5NdYyeZJ1XZ'
                          '0OZ5S9uncurYj2ABWJoVaq/tFCdCEo9bbjWsePei26GZjaM3Fx'
                          'RkAICXe/bt6/uLgaPZtO+sdARDuU3DRKMIdgM9NBaIn0kC7Wk4'
                          'bnYShZ/rbhVt2/ds5XinnDBZsxSR3s553DixJ9v6w9Db++9Stw'
                          '4DgePd9lLy+6WuVBlKmcNflx9zg7US0AOarX2UNiQ==',
                'kdf_length': 32,
                'kdf_salt': 'MYH68QH48nRFMWH44piFWqBnKtU8KCz6Ajh24otrvzJlqPgB'
                            'v6bvFJjRvjRp/0/v1j2nt40RZ6H5hfoKmore0g==\n',
                'length': 1024,
                'cipher': 'aes256',
            }
        }
    }

    def setUp(self):
        def _get_pass():
            return '123'
        self._crypto = SecretsCrypto(_get_pass)

    def test__get_pass(self):
        self.assertEqual(self._crypto._get_pass(), '123')

    def test__get_key(self):
        salt = 'abc'
        expected = scrypt.hash('123', salt, buflen=32)
        key = self._crypto._get_key(salt)
        self.assertEqual(expected, key)

    def test_encrypt(self):
        info = self._crypto.encrypt(self.SECRETS)
        self.assertEqual(8, len(info))
        for key, value in [
                ('kdf', 'scrypt'),
                ('kdf_salt', None),
                ('kdf_length', None),
                ('cipher', 'aes_256_gcm'),
                ('length', None),
                ('iv', None),
                ('secrets', None),
                ('version', 2)]:
            self.assertTrue(key in info)
            if value:
                self.assertEqual(info[key], value)

    def test__decrypt_v2(self):
        encrypted = self.ENCRYPTED_V2
        decrypted = self._crypto.decrypt(encrypted)
        self.assertEqual(decrypted, self.SECRETS)

    def test__decrypt_v1(self):
        encrypted = self.ENCRYPTED_V1
        decrypted = self._crypto.decrypt(encrypted)
        self.assertEqual(decrypted, self.SECRETS)


class SoledadSecretsTestCase(BaseSoledadTest):

    def test_generated_secrets_have_correct_length(self):
        expected = self._soledad.secrets.lengths
        for name, length in expected.iteritems():
            secret = getattr(self._soledad.secrets, name)
            self.assertEqual(length, len(secret))


class SoledadCryptoAESTestCase(BaseSoledadTest):

    def test_encrypt_decrypt_sym(self):
        # generate 256-bit key
        key = os.urandom(32)
        iv, cyphertext = _crypto.encrypt_sym('data', key)
        self.assertTrue(cyphertext is not None)
        self.assertTrue(cyphertext != '')
        self.assertTrue(cyphertext != 'data')
        plaintext = _crypto.decrypt_sym(cyphertext, key, iv)
        self.assertEqual('data', plaintext)

    def test_decrypt_with_wrong_iv_raises(self):
        key = os.urandom(32)
        iv, cyphertext = _crypto.encrypt_sym('data', key)
        self.assertTrue(cyphertext is not None)
        self.assertTrue(cyphertext != '')
        self.assertTrue(cyphertext != 'data')
        # get a different iv by changing the first byte
        rawiv = binascii.a2b_base64(iv)
        wrongiv = rawiv
        while wrongiv == rawiv:
            wrongiv = os.urandom(1) + rawiv[1:]
        with pytest.raises(InvalidTag):
            _crypto.decrypt_sym(
                cyphertext, key, iv=binascii.b2a_base64(wrongiv))

    def test_decrypt_with_wrong_key_raises(self):
        key = os.urandom(32)
        iv, cyphertext = _crypto.encrypt_sym('data', key)
        self.assertTrue(cyphertext is not None)
        self.assertTrue(cyphertext != '')
        self.assertTrue(cyphertext != 'data')
        wrongkey = os.urandom(32)  # 256-bits key
        # ensure keys are different in case we are extremely lucky
        while wrongkey == key:
            wrongkey = os.urandom(32)
        with pytest.raises(InvalidTag):
            _crypto.decrypt_sym(cyphertext, wrongkey, iv)


def _aes_encrypt(key, iv, data):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=backend)
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize(), encryptor.tag


def _aes_decrypt(key, iv, tag, data, aead=''):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=backend)
    decryptor = cipher.decryptor()
    if aead:
        decryptor.authenticate_additional_data(aead)
    return decryptor.update(data) + decryptor.finalize()
