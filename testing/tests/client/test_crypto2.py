# -*- coding: utf-8 -*-
# test_crypto2.py
# Copyright (C) 2016 LEAP Encryption Access Project
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
Tests for the _crypto module
"""

import base64
import binascii
import time
import struct
import StringIO

import leap.soledad.client
from leap.soledad.client import _crypto

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from twisted.trial import unittest


snowden1 = (
    "You can't come up against "
    "the world's most powerful intelligence "
    "agencies and not accept the risk. "
    "If they want to get you, over time "
    "they will.")


def _aes_encrypt(key, iv, data):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=backend)
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def _aes_decrypt(key, iv, data):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=backend)
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()


def test_chunked_encryption():
    key = 'A' * 32
    iv = 'A' * 16

    fd = StringIO.StringIO()
    aes = _crypto.AESEncryptor(key, iv, fd)

    data = snowden1
    block = 16

    for i in range(len(data)/block):
        chunk = data[i * block:(i+1)*block]
        aes.write(chunk)
    aes.end()

    ciphertext_chunked = fd.getvalue()
    ciphertext = _aes_encrypt(key, iv, data)

    assert ciphertext_chunked == ciphertext


def test_decrypt():
    key = 'A' * 32
    iv = 'A' * 16

    data = snowden1
    block = 16

    ciphertext = _aes_encrypt(key, iv, data)

    fd = StringIO.StringIO()
    aes = _crypto.AESDecryptor(key, iv, fd)

    for i in range(len(ciphertext)/block):
        chunk = ciphertext[i * block:(i+1)*block]
        aes.write(chunk)
    aes.end()

    cleartext_chunked = fd.getvalue()
    assert cleartext_chunked == data



class BlobTestCase(unittest.TestCase):

    class doc_info:
        doc_id = 'D-deadbeef'
        rev = '397932e0c77f45fcb7c3732930e7e9b2:1'

    def test_blob_encryptor(self):

        inf = StringIO.StringIO()
        inf.write(snowden1)
        inf.seek(0)
        outf = StringIO.StringIO()

        blob = _crypto.BlobEncryptor(
            self.doc_info, inf, result=outf,
            secret='A' * 96, iv='B'*16)

        d = blob.encrypt()
        d.addCallback(self._test_blob_encryptor_cb, outf)
        return d

    def _test_blob_encryptor_cb(self, _, outf):
        encrypted = outf.getvalue()
        data = base64.urlsafe_b64decode(encrypted)

        assert data[0] == '\x80'
        ts, sch, meth  = struct.unpack(
            'Qbb', data[1:11])
        assert sch == 1
        assert meth == 1
        iv = data[11:27]
        assert iv == 'B' * 16
        doc_id = data[27:37]
        assert doc_id == 'D-deadbeef'

        rev = data[37:71]
        assert rev == self.doc_info.rev

        ciphertext = data[71:-64]
        aes_key = _crypto._get_sym_key_for_doc(
            self.doc_info.doc_id, 'A'*96)
        assert ciphertext == _aes_encrypt(aes_key, 'B'*16, snowden1)

        decrypted = _aes_decrypt(aes_key, 'B'*16, ciphertext)
        assert str(decrypted) == snowden1

    def test_blob_decryptor(self):

        inf = StringIO.StringIO()
        inf.write(snowden1)
        inf.seek(0)
        outf = StringIO.StringIO()

        blob = _crypto.BlobEncryptor(
            self.doc_info, inf, result=outf,
            secret='A' * 96, iv='B' * 16)

        def do_decrypt(_, outf):
            decryptor = _crypto.BlobDecryptor(
                self.doc_info, outf,
                secret='A' * 96)
            d = decryptor.decrypt()
            return d

        d = blob.encrypt()
        d.addCallback(do_decrypt, outf)
        d.addCallback(self._test_blob_decryptor_cb)
        return d

    def _test_blob_decryptor_cb(self, decrypted):
        assert decrypted.getvalue() == snowden1
