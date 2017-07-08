# -*- coding: utf-8 -*-
# preamble.py
# Copyright (C) 2017 LEAP Encryption Access Project
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
Preamble is a binary packed metadata payload present on encrypted documents. It
holds data about encryption scheme, iv, document id and sync related data.
   MAGIC, -> used to differentiate from other data formats
   ENC_SCHEME, -> cryptographic scheme (symmetric or asymmetric)
   ENC_METHOD, -> cipher used, such as AES-GCM or AES-CTR or GPG
   current_time, -> time.time()
   self.iv, -> initialization vector if any, or 0 when not applicable
   str(self.doc_id), -> document id
   str(self.rev), -> current revision
   self._content_size) -> size, rounded to ceiling
"""
import warnings
import struct
import time
from collections import namedtuple
PACMAN = struct.Struct('2sbbQ16s255p255pQ')
LEGACY_PACMAN = struct.Struct('2sbbQ16s255p255p')  # DEPRECATED
MAGIC = '\x13\x37'
ENC_SCHEME = namedtuple('SCHEME', 'symkey external')(1, 2)
ENC_METHOD = namedtuple('METHOD', 'aes_256_ctr aes_256_gcm pgp')(1, 2, 3)


class InvalidPreambleException(Exception):
    pass


class Preamble(object):

    def __init__(self, doc_id, rev, scheme, method,
                 timestamp=0, iv='', magic=None, content_size=0):
        self.doc_id = doc_id
        self.rev = rev
        self.scheme = scheme
        self.method = method
        self.iv = iv
        self.timestamp = int(timestamp) or int(time.time())
        self.magic = magic or MAGIC
        self.content_size = int(content_size)

    def encode(self):
        preamble = PACMAN.pack(
            self.magic,
            self.scheme,
            self.method,
            self.timestamp,
            self.iv,
            str(self.doc_id),
            str(self.rev),
            self.content_size)
        return preamble


def decode_preamble(encoded_preamble):
    preamble_size = len(encoded_preamble)
    try:
        if preamble_size == LEGACY_PACMAN.size:
            unpacked_data = LEGACY_PACMAN.unpack(encoded_preamble)
            magic, sch, meth, ts, iv, doc_id, rev = unpacked_data
            warnings.warn("Decoding a legacy preamble without size. " +
                          "This will be deprecated in 0.12. Doc was: " +
                          "doc_id: %s rev: %s" % (doc_id, rev), Warning)
            return Preamble(doc_id, rev, sch, meth, ts, iv, magic)
        elif preamble_size == PACMAN.size:
            unpacked_data = PACMAN.unpack(encoded_preamble)
            magic, sch, meth, ts, iv, doc_id, rev, size = unpacked_data
            return Preamble(doc_id, rev, sch, meth, ts, iv, magic, int(size))
        else:
            raise InvalidPreambleException("Unexpected preamble size %d",
                                           preamble_size)
    except struct.error as e:
        raise InvalidPreambleException(e)
