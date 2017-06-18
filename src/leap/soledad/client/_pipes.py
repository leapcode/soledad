# -*- coding: utf-8 -*-
# _pipes.py
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
Components for piping data on streams.
"""
from io import BytesIO


__all__ = ['TruncatedTailPipe', 'PreamblePipe']


class TruncatedTailPipe(object):
    """
    Truncate the last `tail_size` bytes from the stream.
    """

    def __init__(self, output=None, tail_size=16):
        self.tail_size = tail_size
        self.output = output or BytesIO()
        self.buffer = BytesIO()

    def write(self, data):
        self.buffer.write(data)
        if self.buffer.tell() > self.tail_size:
            self._truncate_tail()

    def _truncate_tail(self):
        overflow_size = self.buffer.tell() - self.tail_size
        self.buffer.seek(0)
        self.output.write(self.buffer.read(overflow_size))
        remaining = self.buffer.read()
        self.buffer.seek(0)
        self.buffer.write(remaining)
        self.buffer.truncate()

    def close(self):
        return self.output


class PreamblePipe(object):
    """
    Consumes data until a space is found, then calls a callback with it and
    starts forwarding data to consumer returned by this callback.
    """

    def __init__(self, callback):
        self.callback = callback
        self.preamble = BytesIO()
        self.output = None

    def write(self, data):
        if not self.output:
            self._write_preamble(data)
        else:
            self.output.write(data)

    def _write_preamble(self, data):
        if ' ' not in data:
            self.preamble.write(data)
            return
        preamble_chunk, remaining = data.split(' ', 1)
        self.preamble.write(preamble_chunk)
        self.output = self.callback(self.preamble)
        self.output.write(remaining)
