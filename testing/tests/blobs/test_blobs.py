# -*- coding: utf-8 -*-
# test_crypto.py
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
Tests for cryptographic related stuff.
"""
from twisted.trial import unittest
from twisted.internet import defer
from leap.soledad.client._blobs import DecrypterBuffer, BlobManager
from leap.soledad.client import _crypto
from io import BytesIO
from mock import Mock
import mock


class BlobTestCase(unittest.TestCase):

    class doc_info:
        doc_id = 'D-deadbeef'
        rev = '397932e0c77f45fcb7c3732930e7e9b2:1'

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
        doc_id, rev = self.doc_info.doc_id, self.doc_info.rev
        tag = encrypted[-16:]
        buf = DecrypterBuffer(doc_id, rev, self.secret, tag)
        buf.write(encrypted)
        fd, size = buf.close()
        assert fd.getvalue() == 'rosa de foc'

    @defer.inlineCallbacks
    def test_blob_manager_encrypted_upload(self):

        @defer.inlineCallbacks
        def _check_result(uri, data, *args, **kwargs):
            decryptor = _crypto.BlobDecryptor(
                self.doc_info, data,
                armor=False,
                secret=self.secret)
            decrypted = yield decryptor.decrypt()
            assert decrypted.getvalue() == 'up and up'
            defer.returnValue(Mock(code=200))

        manager = BlobManager('', '', self.secret, self.secret, 'user')
        doc_id, rev = self.doc_info.doc_id, self.doc_info.rev
        fd = BytesIO('up and up')
        with mock.patch('leap.soledad.client._blobs.treq.put') as mock_treq:
            mock_treq.side_effect = _check_result
            yield manager._encrypt_and_upload('blob_id', doc_id, rev, fd)
