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

    SECRETS = {'remote': 'a' * 512, 'salt': 'b' * 64, 'local': 'c' * 448}
    ENCRYPTED_V2 = {
        'cipher': 'aes_256_gcm',
        'length': 1417,
        'kdf_salt': '3DCkfecls0GcX2RadA04FAC2cqkI+vpGwwCLwffdRI6vpO5SPxaw/eM0/'
                    'z3GUADm3If3YCQBldKXNdqHQLsU1Q==\n',
        'iv': 'rRwCDw5Rbp5+J3QwjQ46Hw==',
        'secrets': 'lxf6yrGDcBr8XFWNDgsCoO2XPGfDJndviL9Y2GmHcSEBWnO2dm2sieuPoq'
                   'PwSHRSJSrzM4Ezgdaan7X8+ErnuRLUVqbPAqPl8xx8FdCjnid4vFyFYNFI'
                   '/dmo8SQAf8O9vdlVEPZ5Nk2DuWIrh+oPlrSUOmR6XzI0YVdoJDmGWowygU'
                   'MR0R9Bi9xFGlG135NVcNP8KGdnQDkI0V+U/3qm3tctbo4LRCxxJ60wdi0M'
                   'DA6iYFI/IMshxI/ZXFHp5/YPk0k2m0i6z71kMVksgjIMMgT5Kmz7WR54na'
                   'IkWbvNkbYRFR/Hbg9p6Bs7NjJlOLTjnwGJNYPbdyfJXKd1R/S8Mg7ZqsyQ'
                   'VbBqXHwEN7gYlMZ66D8wu8LOK70mN7LLiSz5J8tXO3rDT1mIIf3IvNhv/j'
                   'rEZHf1fTFPRp+ZVEt/hJKyPv71ua4p2lgdgNlCs2IsACk9ku/LQwXP6uZr'
                   'hMJsTvniTQoCVXFYVN/jKo7Pz/+uT5wOXOXtL7smpBE/2r3uoERNM+Zw11'
                   'SA8UzzMZQMxJQKVNwLmKtwvztN5dxVXhxCUyeLmeQc84VzV7NK0WMUOdfA'
                   '18I0HS6rHLKcdsvrPAdzvGim7tiE8TBdp8ITNQ8yMFNiGNyOVliTSTwQFf'
                   'sCj6m5nYcjvprNQ8RkeitvicrtI1Ylc8CfFK50xPV77XVmlgvNsfm54msN'
                   'tV0K5+XwaNgimlh/1m2bVEYj55gO0twVASwRuZj3sSY2z669iuXRk7EPyT'
                   'jcE2NnfW+lqOQkJ73N7pv73t6OjiEnrKx7VmH94zYlY8ZReVVn4RTZhare'
                   'D7rqCmGPhsPaCPaAfotfNBBa0w6p6L9ZlNxpIesnMObtyGob1g4Vcu8O6K'
                   '2Q1Ldj95+Q53tJDpx2NLP/5tfAUlbehD3whKwKOz/rGKEfhgE+Nx32RR0y'
                   'YM4aJ7CYI/U3YH82xqGoa1ufIJbSBt965CVIHSVJt/mYfilhMACV/wBlvL'
                   'ua08iKpHwc7suMc9DuFS4s/bAzc128L8wtfNvNiP6zhAV+UvfgUmyNKjgl'
                   '0be9Ke2pCNChEQmViNal3zbWNcBrXYQpFpX1lWNkx/OuQalxzSaqmZiOR5'
                   'eRwqRDZ3R9EpkOFj2ZXS1NlJg1kYXL/ibS8uvjKgJFPrZQzwaKmPNsZyGc'
                   'CnHupfgC2iRIu97wnvmDxWQ9Cs62NSynr0IYGkTLN5PZU6Z5gd1F7zV6uh'
                   'oFiHOYidj2EoUj7xnb8GHi5U6PQzaC97nSCR4CFnmcpfv+XcRIWe8nrM8G'
                   'AVdcUob8pofUlnyGV6GEGlO3mnb7ls5B6lvuZqB/x6UqZiNKwmZvxvS11X'
                   'AGkhfBGTfFZeqRlLwXvXWnOUOO0KJ8h3gSlc1gFVY+4HCbTOqjUASWw0mV'
                   'JP+U0anK9wu9B/icLDUZxM/NRdbTQFmcfvABjwdm2GTmwGpQek/H0wN3dO'
                   'terlTiS7arMUft7A6hkhkmLb0iDfWPWdN50V+XOMpdZtaJSGqwNHokc75p'
                   '3zYll0/ZpxTgmWXariOkKxr6KHHjml89QNQSBE2TJW/YnQ5SrkaHLHKdcy'
                   'PqQtcXDz/WxKquQfRF+fsvcwqaeqlAWOxUXHU77cBvDGPU5O3uvEIJnHr1'
                   'kuabqRQbJIV5Uzo4sEW828r2IWQnUd4Om79y+9yp/aT10DusEmvOgS3oSp'
                   '3eYkhvlVULeCQEJoI41t4nGLhHiiK4xBG8yFknuV7nF4k2O+EbyCXsJeeD'
                   'qlGok91zEhQl1MlQA8ZofRK7bDPcn97USiJMss81s5bwIv4yN8s0QL62Ha'
                   'vrIYG7C26DV6c0GxULu02H1YOnoPf6JsGC/2+zA+b7a+4O0EP0BXU3FYCb'
                   'iEDbDpB3dFe63ed+ml2HQjqzOLAtKVXzAQq5UNV4m2zY0/y7gV7qSrM='
                   '\n',
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
