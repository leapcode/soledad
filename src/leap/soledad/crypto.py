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


from leap.common.keymanager import openpgp


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
        self._pgp = openpgp.OpenPGPScheme(self._soledad)

    def encrypt_sym(self, data, passphrase):
        """
        Encrypt C{data} using a {password}.

        @param data: the data to be encrypted
        @type data: str
        @param passphrase: the passphrase to use for encryption
        @type passphrase: str

        @return: the encrypted data
        @rtype: str
        """
        return openpgp.encrypt_sym(data, passphrase)

    def decrypt_sym(self, data, passphrase):
        """
        Decrypt data using symmetric secret.

        @param data: the data to be decrypted
        @type data: str
        @param passphrase: the passphrase to use for decryption
        @type passphrase: str

        @return: the decrypted data
        @rtype: str
        """
        return openpgp.decrypt_sym(data, passphrase)

    def is_encrypted(self, data):
        """
        Test whether some chunk of data is a cyphertext.

        @param data: the data to be tested
        @type data: str

        @return: whether the data is a cyphertext
        @rtype: bool
        """
        return openpgp.is_encrypted(data)

    def is_encrypted_sym(self, data):
        """
        Test whether some chunk of data was encrypted with a symmetric key.

        @return: whether data is encrypted to a symmetric key
        @rtype: bool
        """
        return openpgp.is_encrypted_sym(data)

    def doc_passphrase(self, doc_id):
        """
        Generate a passphrase for symmetric encryption of document's contents.

        The password is derived using HMAC having sha256 as underlying hash
        function. The key used for HMAC is Soledad's storage secret stripped
        from the first MAC_KEY_LENGTH characters. The HMAC message is
        C{doc_id}.

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
            self.secret[self.MAC_KEY_LENGTH:],
            doc_id,
            hashlib.sha256).hexdigest()

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
            hashlib.sha256).hexdigest()

    #
    # secret setters/getters
    #

    def _get_secret(self):
        return self._soledad.storage_secret

    secret = property(
        _get_secret, doc='The secret used for symmetric encryption')
