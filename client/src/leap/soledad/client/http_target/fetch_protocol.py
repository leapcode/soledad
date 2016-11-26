# -*- coding: utf-8 -*-
# fetch_protocol.py
# Copyright (C) 2016 LEAP
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
import json
from functools import partial
from cStringIO import StringIO
from twisted.web._newclient import ResponseDone
from leap.soledad.common.l2db import errors
from leap.soledad.common.l2db.remote import utils
from leap.soledad.common.log import getLogger
from .support import ReadBodyProtocol
from .support import readBody

logger = getLogger(__name__)


class DocStreamReceiver(ReadBodyProtocol):
    """
    A protocol implementation that can parse incoming data from server based
    on a line format specified on u1db implementation. Except that we split doc
    attributes from content to ease parsing and increment throughput for larger
    documents.
    [\r\n
    {metadata},\r\n
    {doc_info},\r\n
    {content},\r\n
    ...
    {doc_info},\r\n
    {content},\r\n
    ]
    """

    def __init__(self, response, deferred, doc_reader):
        self.deferred = deferred
        self.status = response.code if response else None
        self.message = response.phrase if response else None
        self.headers = response.headers if response else {}
        self.delimiter = '\r\n'
        self.metadata = ''
        self._doc_reader = doc_reader
        self.reset()

    def reset(self):
        self._line = 0
        self._buffer = StringIO()
        self._properly_finished = False

    def connectionLost(self, reason):
        """
        Deliver the accumulated response bytes to the waiting L{Deferred}, if
        the response body has been completely received without error.
        """
        try:
            if reason.check(ResponseDone):
                self.dataBuffer = self.metadata
            else:
                self.dataBuffer = self.finish()
        except errors.BrokenSyncStream, e:
            return self.deferred.errback(e)
        return ReadBodyProtocol.connectionLost(self, reason)

    def consumeBufferLines(self):
        """
        Consumes lines from buffer and rewind it, writing remaining data
        that didn't formed a line back into buffer.
        """
        content = self._buffer.getvalue()[0:self._buffer.tell()]
        self._buffer.seek(0)
        lines = content.split(self.delimiter)
        self._buffer.write(lines.pop(-1))
        return lines

    def dataReceived(self, data):
        """
        Buffer incoming data until a line breaks comes in. We check only
        the incoming data for efficiency.
        """
        self._buffer.write(data)
        if '\n' not in data:
            return
        lines = self.consumeBufferLines()
        while lines:
            line, _ = utils.check_and_strip_comma(lines.pop(0))
            self.lineReceived(line)
            self._line += 1

    def lineReceived(self, line):
        """
        Protocol implementation.
        0:      [\r\n
        1:      {metadata},\r\n
        (even): {doc_info},\r\n
        (odd):  {data},\r\n
        (last): ]
        """
        if self._properly_finished:
            raise errors.BrokenSyncStream("Reading a finished stream")
        if ']' == line:
            self._properly_finished = True
        elif self._line == 0:
            if line is not '[':
                raise errors.BrokenSyncStream("Invalid start")
        elif self._line == 1:
            self.metadata = line
            if 'error' in self.metadata:
                raise errors.BrokenSyncStream("Error from server: %s" % line)
            self.total = json.loads(line).get('number_of_changes', -1)
        elif (self._line % 2) == 0:
            self.current_doc = json.loads(line)
            if 'error' in self.current_doc:
                raise errors.BrokenSyncStream("Error from server: %s" % line)
        else:
            d = self._doc_reader(
                self.current_doc, line.strip() or None, self.total)
            d.addErrback(self._error)

    def _error(self, reason):
        logger.error(reason)
        self.transport.loseConnection()

    def finish(self):
        """
        Checks that ']' came and stream was properly closed.
        """
        if not self._properly_finished:
            raise errors.BrokenSyncStream('Stream not properly closed')
        content = self._buffer.getvalue()[0:self._buffer.tell()]
        self._buffer.close()
        return content


def build_body_reader(doc_reader):
    """
    Get the documents from a sync stream and call doc_reader on each
    doc received.

    @param doc_reader: Function to be called for processing an incoming doc.
        Will be called with doc metadata (dict parsed from 1st line) and doc
        content (string)
    @type doc_reader: function

    @return: A function that can be called by the http Agent to create and
    configure the proper protocol.
    """
    protocolClass = partial(DocStreamReceiver, doc_reader=doc_reader)
    return partial(readBody, protocolClass=protocolClass)
