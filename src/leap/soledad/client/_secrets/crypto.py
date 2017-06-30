# -*- coding: utf-8 -*-
# _secrets/crypto.py
# Copyright (C) 2016 LEAP
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

import binascii
import json
import os

from leap.soledad.common import soledad_assert
from leap.soledad.common.log import getLogger

from leap.soledad.client._crypto import encrypt_sym, decrypt_sym, ENC_METHOD
from leap.soledad.client._secrets.util import SecretsError
from leap.soledad.client import _scrypt


logger = getLogger(__name__)


class SecretsCrypto(object):

    VERSION = 2

    def __init__(self, soledad):
        self._soledad = soledad

    def _get_key(self, salt):
        passphrase = self._soledad.passphrase.encode('utf8')
        key = _scrypt.hash(passphrase, salt, buflen=32)
        return key

    #
    # encryption
    #

    def encrypt(self, secrets):
        encoded = {}
        for name, value in secrets.iteritems():
            encoded[name] = binascii.b2a_base64(value)
        plaintext = json.dumps(encoded)
        salt = os.urandom(64)  # TODO: get salt length from somewhere else
        key = self._get_key(salt)
        iv, ciphertext = encrypt_sym(plaintext, key,
                                     method=ENC_METHOD.aes_256_gcm)
        encrypted = {
            'version': self.VERSION,
            'kdf': 'scrypt',
            'kdf_salt': binascii.b2a_base64(salt),
            'kdf_length': len(key),
            'cipher': ENC_METHOD.aes_256_gcm,
            'length': len(plaintext),
            'iv': str(iv),
            'secrets': binascii.b2a_base64(ciphertext),
        }
        return encrypted

    #
    # decryption
    #

    def decrypt(self, data):
        version = data.setdefault('version', 1)
        method = getattr(self, '_decrypt_v%d' % version)
        try:
            return method(data)
        except Exception as e:
            logger.error('error decrypting secrets: %r' % e)
            raise SecretsError(e)

    def _decrypt_v1(self, data):
        # get encrypted secret from dictionary: the old format allowed for
        # storage of more than one secret, but this feature was never used and
        # soledad has been using only one secret so far. As there is a corner
        # case where the old 'active_secret' key might not be set, we just
        # ignore it and pop the only secret found in the 'storage_secrets' key.
        secret_id = data['storage_secrets'].keys().pop()
        encrypted = data['storage_secrets'][secret_id]

        # assert that we know how to decrypt the secret
        soledad_assert('cipher' in encrypted)
        cipher = encrypted['cipher']
        if cipher == 'aes256':
            cipher = ENC_METHOD.aes_256_ctr
        soledad_assert(cipher in ENC_METHOD)

        # decrypt
        salt = binascii.a2b_base64(encrypted['kdf_salt'])
        key = self._get_key(salt)
        separator = ':'
        iv, ciphertext = encrypted['secret'].split(separator, 1)
        ciphertext = binascii.a2b_base64(ciphertext)
        plaintext = self._decrypt(key, iv, ciphertext, encrypted, cipher)

        # create secrets dictionary
        secrets = {
            'remote_secret': plaintext[0:512],
            'local_salt': plaintext[512:576],
            'local_secret': plaintext[576:1024],
        }
        return secrets

    def _decrypt_v2(self, encrypted):
        cipher = encrypted['cipher']
        soledad_assert(cipher in ENC_METHOD)

        salt = binascii.a2b_base64(encrypted['kdf_salt'])
        key = self._get_key(salt)
        iv = encrypted['iv']
        ciphertext = binascii.a2b_base64(encrypted['secrets'])
        plaintext = self._decrypt(
            key, iv, ciphertext, encrypted, cipher)
        encoded = json.loads(plaintext)
        secrets = {}
        for name, value in encoded.iteritems():
            secrets[name] = binascii.a2b_base64(value)
        return secrets

    def _decrypt(self, key, iv, ciphertext, encrypted, method):
        # assert some properties of the stored secret
        soledad_assert(encrypted['kdf'] == 'scrypt')
        soledad_assert(encrypted['kdf_length'] == len(key))
        # decrypt
        plaintext = decrypt_sym(ciphertext, key, iv, method)
        soledad_assert(encrypted['length'] == len(plaintext))
        return plaintext
