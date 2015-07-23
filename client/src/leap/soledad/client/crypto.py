# -*- coding: utf-8 -*-
# crypto.py
# Copyright (C) 2013, 2014 LEAP
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
import json
import logging

from pycryptopp.cipher.aes import AES
from pycryptopp.cipher.xsalsa20 import XSalsa20

from leap.soledad.common import soledad_assert
from leap.soledad.common import soledad_assert_type
from leap.soledad.common import crypto


logger = logging.getLogger(__name__)


MAC_KEY_LENGTH = 64


def _assert_known_encryption_method(method):
    """
    Assert that we can encrypt/decrypt the given C{method}

    :param method: The encryption method to assert.
    :type method: str

    :raise UnknownEncryptionMethodError: Raised when C{method} is unknown.
    """
    valid_methods = [
        crypto.EncryptionMethods.AES_256_CTR,
        crypto.EncryptionMethods.XSALSA20,
    ]
    try:
        soledad_assert(method in valid_methods)
    except AssertionError:
        raise crypto.UnknownEncryptionMethodError


def encrypt_sym(data, key, method):
    """
    Encrypt C{data} using a {password}.

    Currently, the only encryption methods supported are AES-256 in CTR
    mode and XSalsa20.

    :param data: The data to be encrypted.
    :type data: str
    :param key: The key used to encrypt C{data} (must be 256 bits long).
    :type key: str
    :param method: The encryption method to use.
    :type method: str

    :return: A tuple with the initial value and the encrypted data.
    :rtype: (long, str)

    :raise AssertionError: Raised if C{method} is unknown.
    """
    soledad_assert_type(key, str)
    soledad_assert(
        len(key) == 32,  # 32 x 8 = 256 bits.
        'Wrong key size: %s bits (must be 256 bits long).' %
        (len(key) * 8))
    _assert_known_encryption_method(method)

    iv = None
    # AES-256 in CTR mode
    if method == crypto.EncryptionMethods.AES_256_CTR:
        iv = os.urandom(16)
        ciphertext = AES(key=key, iv=iv).process(data)
    # XSalsa20
    elif method == crypto.EncryptionMethods.XSALSA20:
        iv = os.urandom(24)
        ciphertext = XSalsa20(key=key, iv=iv).process(data)

    return binascii.b2a_base64(iv), ciphertext


def decrypt_sym(data, key, method, **kwargs):
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

    :raise UnknownEncryptionMethodError: Raised when C{method} is unknown.
    """
    soledad_assert_type(key, str)
    # assert params
    soledad_assert(
        len(key) == 32,  # 32 x 8 = 256 bits.
        'Wrong key size: %s (must be 256 bits long).' % len(key))
    soledad_assert(
        'iv' in kwargs,
        '%s needs an initial value.' % method)
    _assert_known_encryption_method(method)
    # AES-256 in CTR mode
    if method == crypto.EncryptionMethods.AES_256_CTR:
        return AES(
            key=key, iv=binascii.a2b_base64(kwargs['iv'])).process(data)
    elif method == crypto.EncryptionMethods.XSALSA20:
        return XSalsa20(
            key=key, iv=binascii.a2b_base64(kwargs['iv'])).process(data)


def doc_mac_key(doc_id, secret):
    """
    Generate a key for calculating a MAC for a document whose id is
    C{doc_id}.

    The key is derived using HMAC having sha256 as underlying hash
    function. The key used for HMAC is the first MAC_KEY_LENGTH characters
    of Soledad's storage secret. The HMAC message is C{doc_id}.

    :param doc_id: The id of the document.
    :type doc_id: str

    :param secret: The Soledad storage secret
    :type secret: str

    :return: The key.
    :rtype: str
    """
    soledad_assert(secret is not None)
    return hmac.new(
        secret[:MAC_KEY_LENGTH],
        doc_id,
        hashlib.sha256).digest()


class SoledadCrypto(object):
    """
    General cryptographic functionality encapsulated in a
    object that can be passed along.
    """
    def __init__(self, soledad):
        """
        Initialize the crypto object.

        :param soledad: A Soledad instance for key lookup.
        :type soledad: leap.soledad.Soledad
        """
        self._soledad = soledad

    def encrypt_sym(self, data, key,
                    method=crypto.EncryptionMethods.AES_256_CTR):
        return encrypt_sym(data, key, method)

    def decrypt_sym(self, data, key,
                    method=crypto.EncryptionMethods.AES_256_CTR, **kwargs):
        return decrypt_sym(data, key, method, **kwargs)

    def doc_mac_key(self, doc_id, secret):
        return doc_mac_key(doc_id, self.secret)

    def doc_passphrase(self, doc_id):
        """
        Generate a passphrase for symmetric encryption of document's contents.

        The password is derived using HMAC having sha256 as underlying hash
        function. The key used for HMAC are the first
        C{soledad.REMOTE_STORAGE_SECRET_LENGTH} bytes of Soledad's storage
        secret stripped from the first MAC_KEY_LENGTH characters. The HMAC
        message is C{doc_id}.

        :param doc_id: The id of the document that will be encrypted using
            this passphrase.
        :type doc_id: str

        :return: The passphrase.
        :rtype: str
        """
        soledad_assert(self.secret is not None)
        return hmac.new(
            self.secret[MAC_KEY_LENGTH:],
            doc_id,
            hashlib.sha256).digest()

    #
    # secret setters/getters
    #

    def _get_secret(self):
        return self._soledad.secrets.remote_storage_secret

    secret = property(
        _get_secret, doc='The secret used for symmetric encryption')


#
# Crypto utilities for a SoledadDocument.
#

def mac_doc(doc_id, doc_rev, ciphertext, enc_scheme, enc_method, enc_iv,
            mac_method, secret):
    """
    Calculate a MAC for C{doc} using C{ciphertext}.

    Current MAC method used is HMAC, with the following parameters:

        * key: sha256(storage_secret, doc_id)
        * msg: doc_id + doc_rev + ciphertext
        * digestmod: sha256

    :param doc_id: The id of the document.
    :type doc_id: str
    :param doc_rev: The revision of the document.
    :type doc_rev: str
    :param ciphertext: The content of the document.
    :type ciphertext: str
    :param enc_scheme: The encryption scheme.
    :type enc_scheme: str
    :param enc_method: The encryption method.
    :type enc_method: str
    :param enc_iv: The encryption initialization vector.
    :type enc_iv: str
    :param mac_method: The MAC method to use.
    :type mac_method: str
    :param secret: The Soledad storage secret
    :type secret: str

    :return: The calculated MAC.
    :rtype: str

    :raise crypto.UnknownMacMethodError: Raised when C{mac_method} is unknown.
    """
    try:
        soledad_assert(mac_method == crypto.MacMethods.HMAC)
    except AssertionError:
        raise crypto.UnknownMacMethodError
    template = "{doc_id}{doc_rev}{ciphertext}{enc_scheme}{enc_method}{enc_iv}"
    content = template.format(
        doc_id=doc_id,
        doc_rev=doc_rev,
        ciphertext=ciphertext,
        enc_scheme=enc_scheme,
        enc_method=enc_method,
        enc_iv=enc_iv)
    return hmac.new(
        doc_mac_key(doc_id, secret),
        content,
        hashlib.sha256).digest()


def encrypt_doc(crypto, doc):
    """
    Wrapper around encrypt_docstr that accepts a crypto object and the document
    as arguments.

    :param crypto: a soledad crypto object.
    :type crypto: SoledadCrypto
    :param doc: the document.
    :type doc: SoledadDocument
    """
    key = crypto.doc_passphrase(doc.doc_id)
    secret = crypto.secret

    return encrypt_docstr(
        doc.get_json(), doc.doc_id, doc.rev, key, secret)


def encrypt_docstr(docstr, doc_id, doc_rev, key, secret):
    """
    Encrypt C{doc}'s content.

    Encrypt doc's contents using AES-256 CTR mode and return a valid JSON
    string representing the following:

        {
            crypto.ENC_JSON_KEY: '<encrypted doc JSON string>',
            crypto.ENC_SCHEME_KEY: 'symkey',
            crypto.ENC_METHOD_KEY: crypto.EncryptionMethods.AES_256_CTR,
            crypto.ENC_IV_KEY: '<the initial value used to encrypt>',
            MAC_KEY: '<mac>'
            crypto.MAC_METHOD_KEY: 'hmac'
        }

    :param docstr: A representation of the document to be encrypted.
    :type docstr: str or unicode.

    :param doc_id: The document id.
    :type doc_id: str

    :param doc_rev: The document revision.
    :type doc_rev: str

    :param key: The key used to encrypt ``data`` (must be 256 bits long).
    :type key: str

    :param secret: The Soledad storage secret (used for MAC auth).
    :type secret: str

    :return: The JSON serialization of the dict representing the encrypted
             content.
    :rtype: str
    """
    enc_scheme = crypto.EncryptionSchemes.SYMKEY
    enc_method = crypto.EncryptionMethods.AES_256_CTR
    mac_method = crypto.MacMethods.HMAC
    enc_iv, ciphertext = encrypt_sym(
        str(docstr),  # encryption/decryption routines expect str
        key, method=enc_method)
    mac = binascii.b2a_hex(  # store the mac as hex.
        mac_doc(
            doc_id,
            doc_rev,
            ciphertext,
            enc_scheme,
            enc_method,
            enc_iv,
            mac_method,
            secret))
    # Return a representation for the encrypted content. In the following, we
    # convert binary data to hexadecimal representation so the JSON
    # serialization does not complain about what it tries to serialize.
    hex_ciphertext = binascii.b2a_hex(ciphertext)
    logger.debug("Encrypting doc: %s" % doc_id)
    return json.dumps({
        crypto.ENC_JSON_KEY: hex_ciphertext,
        crypto.ENC_SCHEME_KEY: enc_scheme,
        crypto.ENC_METHOD_KEY: enc_method,
        crypto.ENC_IV_KEY: enc_iv,
        crypto.MAC_KEY: mac,
        crypto.MAC_METHOD_KEY: mac_method,
    })


def decrypt_doc(crypto, doc):
    """
    Wrapper around decrypt_doc_dict that accepts a crypto object and the
    document as arguments.

    :param crypto: a soledad crypto object.
    :type crypto: SoledadCrypto
    :param doc: the document.
    :type doc: SoledadDocument

    :return: json string with the decrypted document
    :rtype: str
    """
    key = crypto.doc_passphrase(doc.doc_id)
    secret = crypto.secret
    return decrypt_doc_dict(doc.content, doc.doc_id, doc.rev, key, secret)


def _verify_doc_mac(doc_id, doc_rev, ciphertext, enc_scheme, enc_method,
                    enc_iv, mac_method, secret, doc_mac):
    """
    Verify that C{doc_mac} is a correct MAC for the given document.

    :param doc_id: The id of the document.
    :type doc_id: str
    :param doc_rev: The revision of the document.
    :type doc_rev: str
    :param ciphertext: The content of the document.
    :type ciphertext: str
    :param enc_scheme: The encryption scheme.
    :type enc_scheme: str
    :param enc_method: The encryption method.
    :type enc_method: str
    :param enc_iv: The encryption initialization vector.
    :type enc_iv: str
    :param mac_method: The MAC method to use.
    :type mac_method: str
    :param secret: The Soledad storage secret
    :type secret: str
    :param doc_mac: The MAC to be verified against.
    :type doc_mac: str

    :raise crypto.UnknownMacMethodError: Raised when C{mac_method} is unknown.
    :raise crypto.WrongMacError: Raised when MAC could not be verified.
    """
    calculated_mac = mac_doc(
        doc_id,
        doc_rev,
        ciphertext,
        enc_scheme,
        enc_method,
        enc_iv,
        mac_method,
        secret)
    # we compare mac's hashes to avoid possible timing attacks that might
    # exploit python's builtin comparison operator behaviour, which fails
    # immediatelly when non-matching bytes are found.
    doc_mac_hash = hashlib.sha256(
        binascii.a2b_hex(  # the mac is stored as hex
            doc_mac)).digest()
    calculated_mac_hash = hashlib.sha256(calculated_mac).digest()

    if doc_mac_hash != calculated_mac_hash:
        logger.warning("Wrong MAC while decrypting doc...")
        raise crypto.WrongMacError("Could not authenticate document's "
                                   "contents.")


def decrypt_doc_dict(doc_dict, doc_id, doc_rev, key, secret):
    """
    Decrypt a symmetrically encrypted C{doc}'s content.

    Return the JSON string representation of the document's decrypted content.

    The passed doc_dict argument should have the following structure:

        {
            crypto.ENC_JSON_KEY: '<enc_blob>',
            crypto.ENC_SCHEME_KEY: '<enc_scheme>',
            crypto.ENC_METHOD_KEY: '<enc_method>',
            crypto.ENC_IV_KEY: '<initial value used to encrypt>',  # (optional)
            MAC_KEY: '<mac>'
            crypto.MAC_METHOD_KEY: 'hmac'
        }

    C{enc_blob} is the encryption of the JSON serialization of the document's
    content. For now Soledad just deals with documents whose C{enc_scheme} is
    crypto.EncryptionSchemes.SYMKEY and C{enc_method} is
    crypto.EncryptionMethods.AES_256_CTR.

    :param doc_dict: The content of the document to be decrypted.
    :type doc_dict: dict

    :param doc_id: The document id.
    :type doc_id: str

    :param doc_rev: The document revision.
    :type doc_rev: str

    :param key: The key used to encrypt ``data`` (must be 256 bits long).
    :type key: str

    :param secret:
    :type secret:

    :return: The JSON serialization of the decrypted content.
    :rtype: str

    :raise UnknownEncryptionMethodError: Raised when trying to decrypt from an
        unknown encryption method.
    """
    # assert document dictionary structure
    expected_keys = set([
        crypto.ENC_JSON_KEY,
        crypto.ENC_SCHEME_KEY,
        crypto.ENC_METHOD_KEY,
        crypto.ENC_IV_KEY,
        crypto.MAC_KEY,
        crypto.MAC_METHOD_KEY,
    ])
    soledad_assert(expected_keys.issubset(set(doc_dict.keys())))

    ciphertext = binascii.a2b_hex(doc_dict[crypto.ENC_JSON_KEY])
    enc_scheme = doc_dict[crypto.ENC_SCHEME_KEY]
    enc_method = doc_dict[crypto.ENC_METHOD_KEY]
    enc_iv = doc_dict[crypto.ENC_IV_KEY]
    doc_mac = doc_dict[crypto.MAC_KEY]
    mac_method = doc_dict[crypto.MAC_METHOD_KEY]

    soledad_assert(enc_scheme == crypto.EncryptionSchemes.SYMKEY)

    _verify_doc_mac(
        doc_id, doc_rev, ciphertext, enc_scheme, enc_method,
        enc_iv, mac_method, secret, doc_mac)

    return decrypt_sym(ciphertext, key, method=enc_method, iv=enc_iv)


def is_symmetrically_encrypted(doc):
    """
    Return True if the document was symmetrically encrypted.

    :param doc: The document to check.
    :type doc: SoledadDocument

    :rtype: bool
    """
    if doc.content and crypto.ENC_SCHEME_KEY in doc.content:
        if doc.content[crypto.ENC_SCHEME_KEY] \
                == crypto.EncryptionSchemes.SYMKEY:
            return True
    return False
