# -*- coding: utf-8 -*-
# test_blobs.py
# Copyright (C) 2017 LEAP
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
Tests for blobs decrypter buffer. A component which is used as a decryption
sink during blob stream download.
"""
from io import BytesIO
from mock import Mock

from twisted.trial import unittest
from twisted.internet import defer

from leap.soledad.client._db.blobs import DecrypterBuffer
from leap.soledad.client._db.blobs import BlobManager
from leap.soledad.client._db.blobs import FIXED_REV
from leap.soledad.client import _crypto


class DecrypterBufferCase(unittest.TestCase):

    class doc_info:
        doc_id = 'D-BLOB-ID'
        rev = FIXED_REV

    def setUp(self):
        self.cleartext = BytesIO('rosa de foc')
        self.secret = 'A' * 96
        self.blob = _crypto.BlobEncryptor(
            self.doc_info, self.cleartext,
            armor=False,
            secret='A' * 96)

    @defer.inlineCallbacks
    def test_decrypt_buffer(self):
        encrypted = (yield self.blob.encrypt()).getvalue()
        tag = encrypted[-16:]
        buf = DecrypterBuffer(self.doc_info.doc_id, self.secret, tag)
        buf.write(encrypted)
        fd, size = buf.close()
        self.assertEquals(fd.getvalue(), 'rosa de foc')

    @defer.inlineCallbacks
    def test_decrypt_uploading_encrypted_blob(self):

        @defer.inlineCallbacks
        def _check_result(uri, data, *args, **kwargs):
            decryptor = _crypto.BlobDecryptor(
                self.doc_info, data,
                armor=False,
                secret=self.secret)
            decrypted = yield decryptor.decrypt()
            self.assertEquals(decrypted.getvalue(), 'up and up')
            defer.returnValue(Mock(code=200))

        manager = BlobManager('', '', self.secret, self.secret, 'user')
        fd = BytesIO('up and up')
        manager._client.put = _check_result
        yield manager._encrypt_and_upload(self.doc_info.doc_id, fd)
