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
Soledad common crypto bits.
"""


#
# Encryption schemes used for encryption.
#

class EncryptionSchemes(object):

    """
    Representation of encryption schemes used to encrypt documents.
    """

    NONE = 'none'
    SYMKEY = 'symkey'
    PUBKEY = 'pubkey'


class UnknownEncryptionSchemeError(Exception):

    """
    Raised when trying to decrypt from unknown encryption schemes.
    """
    pass


class EncryptionMethods(object):

    """
    Representation of encryption methods that can be used.
    """

    AES_256_CTR = 'aes-256-ctr'


class UnknownEncryptionMethodError(Exception):

    """
    Raised when trying to encrypt/decrypt with unknown method.
    """
    pass


class MacMethods(object):

    """
    Representation of MAC methods used to authenticate document's contents.
    """

    HMAC = 'hmac'


class UnknownMacMethodError(Exception):

    """
    Raised when trying to authenticate document's content with unknown MAC
    mehtod.
    """
    pass


class WrongMacError(Exception):

    """
    Raised when failing to authenticate document's contents based on MAC.
    """


#
# Crypto utilities for a SoledadDocument.
#

ENC_JSON_KEY = '_enc_json'
ENC_SCHEME_KEY = '_enc_scheme'
ENC_METHOD_KEY = '_enc_method'
ENC_IV_KEY = '_enc_iv'
MAC_KEY = '_mac'
MAC_METHOD_KEY = '_mac_method'
