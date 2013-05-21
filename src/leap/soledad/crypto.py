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


import hmac
import hashlib


from leap.common import crypto


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

        @param soledad: A Soledad instance for key lookup.
        @type soledad: leap.soledad.Soledad
        """
        self._soledad = soledad

    def encrypt_sym(self, data, key,
                    method=crypto.EncryptionMethods.AES_256_CTR):
        """
        Encrypt C{data} using a {password}.

        Currently, the only  encryption method supported is AES-256 CTR mode.

        @param data: The data to be encrypted.
        @type data: str
        @param key: The key used to encrypt C{data} (must be 256 bits long).
        @type key: str
        @param method: The encryption method to use.
        @type method: str

        @return: A tuple with the initial value and the encrypted data.
        @rtype: (long, str)
        """
        return crypto.encrypt_sym(data, key, method)

    def decrypt_sym(self, data, key,
                    method=crypto.EncryptionMethods.AES_256_CTR, **kwargs):
        """
        Decrypt data using symmetric secret.

        Currently, the only encryption method supported is AES-256 CTR mode.

        @param data: The data to be decrypted.
        @type data: str
        @param key: The key used to decrypt C{data} (must be 256 bits long).
        @type key: str
        @param method: The encryption method to use.
        @type method: str
        @param kwargs: Other parameters specific to each encryption method.
        @type kwargs: dict

        @return: The decrypted data.
        @rtype: str
        """
        return crypto.decrypt_sym(data, key, method, **kwargs)

    def doc_passphrase(self, doc_id):
        """
        Generate a passphrase for symmetric encryption of document's contents.

        The password is derived using HMAC having sha256 as underlying hash
        function. The key used for HMAC are the first
        C{soledad.REMOTE_STORAGE_SECRET_KENGTH} bytes of Soledad's storage
        secret stripped from the first MAC_KEY_LENGTH characters. The HMAC
        message is C{doc_id}.

        @param doc_id: The id of the document that will be encrypted using
            this passphrase.
        @type doc_id: str

        @return: The passphrase.
        @rtype: str

        @raise NoSymmetricSecret: if no symmetric secret was supplied.
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

        @param doc_id: The id of the document.
        @type doc_id: str

        @return: The key.
        @rtype: str

        @raise NoSymmetricSecret: if no symmetric secret was supplied.
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
