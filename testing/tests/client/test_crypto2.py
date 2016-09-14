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

import StringIO


import leap.soledad.client
from leap.soledad.client import _crypto


from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def _aes_encrypt(key, iv, data):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=backend)
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


def test_chunked_encryption():
    key = 'A' * 32
    iv = 'A' * 16
    data = (
        "You can't come up against "
        "the world's most powerful intelligence "
        "agencies and not accept the risk. "
        "If they want to get you, over time "
        "they will.")

    fd = StringIO.StringIO()
    aes = _crypto.AESWriter(key, fd, iv)

    block = 16

    for i in range(len(data)/block):
        chunk = data[i * block:(i+1)*block]
        aes.write(chunk)
    aes.end()

    ciphertext_chunked = fd.getvalue()
    ciphertext = _aes_encrypt(key, iv, data)

    assert ciphertext_chunked == ciphertext
