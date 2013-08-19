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


class MacMethods(object):
    """
    Representation of MAC methods used to authenticate document's contents.
    """

    HMAC = 'hmac'


#
# Crypto utilities for a SoledadDocument.
#

ENC_JSON_KEY = '_enc_json'
ENC_SCHEME_KEY = '_enc_scheme'
ENC_METHOD_KEY = '_enc_method'
ENC_IV_KEY = '_enc_iv'
MAC_KEY = '_mac'
MAC_METHOD_KEY = '_mac_method'
