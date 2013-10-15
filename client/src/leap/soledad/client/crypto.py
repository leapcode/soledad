# -*- coding: utf-8 -*-
# crypto.py
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
Cryptographic utilities for Soledad.
"""


import os
import binascii
import hmac
import hashlib


from pycryptopp.cipher.aes import AES
from pycryptopp.cipher.xsalsa20 import XSalsa20


from leap.soledad.common import (
    soledad_assert,
    soledad_assert_type,
)


class EncryptionMethods(object):
    """
    Representation of encryption methods that can be used.
    """

    AES_256_CTR = 'aes-256-ctr'
    XSALSA20 = 'xsalsa20'


class UnknownEncryptionMethod(Exception):
    """
    Raised when trying to encrypt/decrypt with unknown method.
    """
    pass


class NoSymmetricSecret(Exception):
    """
    Raised when trying to get a hashed passphrase.
    """


class SoledadCrypto(object):
    """
    General cryptographic functionality.
    """

    MAC_KEY_LENGTH = 64

    def __init__(self, soledad):
        """
        Initialize the crypto object.

        :param soledad: A Soledad instance for key lookup.
        :type soledad: leap.soledad.Soledad
        """
        self._soledad = soledad

    def encrypt_sym(self, data, key,
                    method=EncryptionMethods.AES_256_CTR):
        """
        Encrypt C{data} using a {password}.

        Currently, the only  encryption method supported is AES-256 CTR mode.

        :param data: The data to be encrypted.
        :type data: str
        :param key: The key used to encrypt C{data} (must be 256 bits long).
        :type key: str
        :param method: The encryption method to use.
        :type method: str

        :return: A tuple with the initial value and the encrypted data.
        :rtype: (long, str)
        """
        soledad_assert_type(key, str)

        soledad_assert(
            len(key) == 32,  # 32 x 8 = 256 bits.
            'Wrong key size: %s bits (must be 256 bits long).' %
            (len(key) * 8))
        iv = None
        # AES-256 in CTR mode
        if method == EncryptionMethods.AES_256_CTR:
            iv = os.urandom(16)
            ciphertext = AES(key=key, iv=iv).process(data)
        # XSalsa20
        elif method == EncryptionMethods.XSALSA20:
            iv = os.urandom(24)
            ciphertext = XSalsa20(key=key, iv=iv).process(data)
        else:
            # raise if method is unknown
            raise UnknownEncryptionMethod('Unkwnown method: %s' % method)
        return binascii.b2a_base64(iv), ciphertext

    def decrypt_sym(self, data, key,
                    method=EncryptionMethods.AES_256_CTR, **kwargs):
        """
        Decrypt data using symmetric secret.

        Currently, the only encryption method supported is AES-256 CTR mode.

        :param data: The data to be decrypted.
        :type data: str
        :param key: The key used to decrypt C{data} (must be 256 bits long).
        :type key: str
        :param method: The encryption method to use.
        :type method: str
        :param kwargs: Other parameters specific to each encryption method.
        :type kwargs: dict

        :return: The decrypted data.
        :rtype: str
        """
        soledad_assert_type(key, str)
        # assert params
        soledad_assert(
            len(key) == 32,  # 32 x 8 = 256 bits.
            'Wrong key size: %s (must be 256 bits long).' % len(key))
        soledad_assert(
            'iv' in kwargs,
            '%s needs an initial value.' % method)
        # AES-256 in CTR mode
        if method == EncryptionMethods.AES_256_CTR:
            return AES(
                key=key, iv=binascii.a2b_base64(kwargs['iv'])).process(data)
        elif method == EncryptionMethods.XSALSA20:
            return XSalsa20(
                key=key, iv=binascii.a2b_base64(kwargs['iv'])).process(data)

        # raise if method is unknown
        raise UnknownEncryptionMethod('Unkwnown method: %s' % method)

    def doc_passphrase(self, doc_id):
        """
        Generate a passphrase for symmetric encryption of document's contents.

        The password is derived using HMAC having sha256 as underlying hash
        function. The key used for HMAC are the first
        C{soledad.REMOTE_STORAGE_SECRET_KENGTH} bytes of Soledad's storage
        secret stripped from the first MAC_KEY_LENGTH characters. The HMAC
        message is C{doc_id}.

        :param doc_id: The id of the document that will be encrypted using
            this passphrase.
        :type doc_id: str

        :return: The passphrase.
        :rtype: str

        :raise NoSymmetricSecret: if no symmetric secret was supplied.
        """
        if self.secret is None:
            raise NoSymmetricSecret()
        return hmac.new(
            self.secret[
                self.MAC_KEY_LENGTH:
                self._soledad.REMOTE_STORAGE_SECRET_LENGTH],
            doc_id,
            hashlib.sha256).digest()

    def doc_mac_key(self, doc_id):
        """
        Generate a key for calculating a MAC for a document whose id is
        C{doc_id}.

        The key is derived using HMAC having sha256 as underlying hash
        function. The key used for HMAC is the first MAC_KEY_LENGTH characters
        of Soledad's storage secret. The HMAC message is C{doc_id}.

        :param doc_id: The id of the document.
        :type doc_id: str

        :return: The key.
        :rtype: str

        :raise NoSymmetricSecret: if no symmetric secret was supplied.
        """
        if self.secret is None:
            raise NoSymmetricSecret()
        return hmac.new(
            self.secret[:self.MAC_KEY_LENGTH],
            doc_id,
            hashlib.sha256).digest()

    #
    # secret setters/getters
    #

    def _get_secret(self):
        return self._soledad.storage_secret

    secret = property(
        _get_secret, doc='The secret used for symmetric encryption')
