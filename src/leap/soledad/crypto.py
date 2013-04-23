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


from binascii import b2a_base64
from hashlib import sha256


from leap.common.keymanager import KeyManager
from leap.soledad.util import GPGWrapper


class NoSymmetricSecret(Exception):
    """
    Raised when trying to get a hashed passphrase.
    """


class SoledadCrypto(object):
    """
    General cryptographic functionality.
    """

    def __init__(self, gnupg_home, symkey=None):
        """
        Initialize the crypto object.

        @param gnupg_home: Home of the gpg instance.
        @type gnupg_home: str
        @param symkey: A key to use for symmetric encryption.
        @type symkey: str
        """
        self._gpg = GPGWrapper(gnupghome=gnupg_home)
        self._symkey = symkey

    def encrypt(self, data, recipients=None, sign=None, passphrase=None,
                symmetric=False):
        """
        Encrypt data.

        @param data: the data to be encrypted
        @type data: str
        @param recipients: to whom C{data} should be encrypted 
        @type recipients: list or str
        @param sign: the fingerprint of key to be used for signature
        @type sign: str
        @param passphrase: the passphrase to be used for encryption
        @type passphrase: str
        @param symmetric: whether the encryption scheme should be symmetric
        @type symmetric: bool

        @return: the encrypted data
        @rtype: str
        """
        return str(self._gpg.encrypt(data, recipients, sign=sign,
                                     passphrase=passphrase,
                                     symmetric=symmetric))

    def encrypt_symmetric(self, data, passphrase, sign=None):
        """
        Encrypt C{data} using a {password}.

        @param data: the data to be encrypted
        @type data: str
        @param passphrase: the passphrase to use for encryption
        @type passphrase: str
        @param data: the data to be encrypted
        @param sign: the fingerprint of key to be used for signature
        @type sign: str

        @return: the encrypted data
        @rtype: str
        """
        return self.encrypt(data, sign=sign,
                            passphrase=passphrase,
                            symmetric=True)

    def decrypt(self, data, passphrase=None):
        """
        Decrypt data.

        @param data: the data to be decrypted
        @type data: str
        @param passphrase: the passphrase to be used for decryption
        @type passphrase: str

        @return: the decrypted data
        @rtype: str
        """
        return str(self._gpg.decrypt(data, passphrase=passphrase))

    def decrypt_symmetric(self, data, passphrase):
        """
        Decrypt data using symmetric secret.

        @param data: the data to be decrypted
        @type data: str
        @param passphrase: the passphrase to use for decryption
        @type passphrase: str

        @return: the decrypted data
        @rtype: str
        """
        return self.decrypt(data, passphrase=passphrase)

    def is_encrypted(self, data):
        """
        Test whether some chunk of data is a cyphertext.

        @param data: the data to be tested
        @type data: str

        @return: whether the data is a cyphertext
        @rtype: bool
        """
        return self._gpg.is_encrypted(data)

    def is_encrypted_sym(self, data):
        """
        Test whether some chunk of data was encrypted with a symmetric key.

        @return: whether data is encrypted to a symmetric key
        @rtype: bool
        """
        return self._gpg.is_encrypted_sym(data)

    def is_encrypted_asym(self, data):
        """
        Test whether some chunk of data was encrypted to an OpenPGP private
        key.

        @return: whether data is encrypted to an OpenPGP private key
        @rtype: bool
        """
        return self._gpg.is_encrypted_asym(data)

    def _hash_passphrase(self, suffix):
        """
        Generate a passphrase for symmetric encryption.

        The password is derived from C{suffix} and the secret for
        symmetric encryption previously loaded.

        @param suffix: Will be appended to the symmetric key before hashing.
        @type suffix: str

        @return: the passphrase
        @rtype: str
        @raise NoSymmetricSecret: if no symmetric secret was supplied.
        """
        if self._symkey is None:
            raise NoSymmetricSecret()
        return b2a_base64(
            sha256('%s%s' % (self._symkey, suffix)).digest())[:-1]

   #
   # symkey setters/getters
   #

    def _get_symkey(self):
        return self._symkey

    def _set_symkey(self, symkey):
        self._symkey = symkey

    symkey = property(_get_symkey, _set_symkey,
                      doc='The key used for symmetric encryption')
