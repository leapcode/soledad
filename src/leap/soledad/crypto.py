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


from hashlib import sha256


from leap.common.keymanager import openpgp


class NoSymmetricSecret(Exception):
    """
    Raised when trying to get a hashed passphrase.
    """


class SoledadCrypto(object):
    """
    General cryptographic functionality.
    """

    def __init__(self, soledad):
        """
        Initialize the crypto object.

        @param soledad: A Soledad instance for key lookup.
        @type soledad: leap.soledad.Soledad
        """
        self._soledad = soledad
        self._pgp = openpgp.OpenPGPScheme(self._soledad)
        self._secret = None

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

    def passphrase_hash(self, suffix):
        """
        Generate a passphrase for symmetric encryption.

        The password is derived from the secret for symmetric encryption and
        a C{suffix} that is appended to the secret prior to hashing.

        @param suffix: Will be appended to the symmetric key before hashing.
        @type suffix: str

        @return: the passphrase
        @rtype: str
        @raise NoSymmetricSecret: if no symmetric secret was supplied.
        """
        if self._secret is None:
            raise NoSymmetricSecret()
        return sha256('%s%s' % (self._secret, suffix)).hexdigest()

    #
    # secret setters/getters
    #

    def _get_secret(self):
        return self._secret

    def _set_secret(self, secret):
        self._secret = secret

    secret = property(_get_secret, _set_secret,
                      doc='The key used for symmetric encryption')
