#!/usr/bin/env python

# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""
Example using stdio, Deferreds, LineReceiver and twisted.web.client.

Note that the WebCheckerCommandProtocol protocol could easily be used in e.g.
a telnet server instead; see the comments for details.

Based on an example by Abe Fettig.
"""
import sys
import json
import warnings
from cStringIO import StringIO
from twisted.internet import reactor
from twisted.internet import defer
from twisted.internet import protocol
from twisted.web.client import HTTPConnectionPool
from twisted.web._newclient import ResponseDone
from twisted.web._newclient import PotentialDataLoss
from twisted.web.client import PartialDownloadError
from leap.soledad.common.l2db import errors
from leap.soledad.common.l2db.remote import utils
from leap.soledad.common.l2db.remote import http_errors
from leap.common.http import HTTPClient


class DocStreamReceiver(protocol.Protocol):

    def __init__(self, response, deferred, doc_reader):
        self.deferred = deferred
        self.status = response.code if response else None
        self.message = response.phrase if response else None
        self.headers = response.headers if response else {}
        self.delimiter = '\r\n'
        self._doc_reader = doc_reader
        self.reset()

    def reset(self):
        self._line = 0
        self._buffer = StringIO()
        self._properly_finished = False

    # ---8<--- snippet from u1db.remote.http_client, modified to use errbacks
    def _error(self, respdic):
        descr = respdic.get("error")
        exc_cls = errors.wire_description_to_exc.get(descr)
        if exc_cls is not None:
            message = respdic.get("message")
            self.deferred.errback(exc_cls(message))
    # ---8<--- end of snippet from u1db.remote.http_client

    def connectionLost(self, reason):
        """
        Deliver the accumulated response bytes to the waiting L{Deferred}, if
        the response body has been completely received without error.
        """
        if reason.check(ResponseDone):

            try:
                body = self.finish()
            except errors.BrokenSyncStream, e:
                return self.deferred.errback(e)

            # ---8<--- snippet from u1db.remote.http_client
            if self.status in (200, 201):
                self.deferred.callback(self.metadata)
            elif self.status in http_errors.ERROR_STATUSES:
                try:
                    respdic = json.loads(body)
                except ValueError:
                    self.deferred.errback(
                        errors.HTTPError(self.status, body, self.headers))
                else:
                    self._error(respdic)
            # special cases
            elif self.status == 503:
                self.deferred.errback(errors.Unavailable(body, self.headers))
            else:
                self.deferred.errback(
                    errors.HTTPError(self.status, body, self.headers))
            # ---8<--- end of snippet from u1db.remote.http_client

        elif reason.check(PotentialDataLoss):
            self.deferred.errback(
                PartialDownloadError(self.status, self.message,
                                     b''.join(body)))
        else:
            self.deferred.errback(reason)

    def consumeBufferLines(self):
        content = self._buffer.getvalue()[0:self._buffer.tell()]
        self._buffer.seek(0)
        lines = content.split(self.delimiter)
        self._buffer.write(lines.pop(-1))
        return lines

    def dataReceived(self, data):
        self._buffer.write(data)
        if '\n' not in data:
            return
        lines = self.consumeBufferLines()
        while lines:
            line, _ = utils.check_and_strip_comma(lines.pop(0))
            try:
                self.lineReceived(line)
            except AssertionError, e:
                raise errors.BrokenSyncStream(e)

    def lineReceived(self, line):
        assert not self._properly_finished
        if ']' == line:
            self._properly_finished = True
        elif self._line == 0:
            assert line == '['
            self._line += 1
        elif self._line == 1:
            self._line += 1
            self.metadata = json.loads(line)
            assert 'error' not in self.metadata
        elif (self._line % 2) == 0:
            self._line += 1
            self.current_doc = json.loads(line)
            assert 'error' not in self.current_doc
        else:
            self._line += 1
            self._doc_reader(self.current_doc, line.strip() or None)

    def finish(self):
        if not self._properly_finished:
            raise errors.BrokenSyncStream()
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
    @type response: function

    @return: A L{Deferred} which will fire with the sync metadata.
        Cancelling it will close the connection to the server immediately.
    """
    def read(response):
        def cancel(deferred):
            """
            Cancel a L{readBody} call, close the connection to the HTTP server
            immediately, if it is still open.

            @param deferred: The cancelled L{defer.Deferred}.
            """
            abort = getAbort()
            if abort is not None:
                abort()

        def getAbort():
            return getattr(protocol.transport, 'abortConnection', None)

        d = defer.Deferred(cancel)
        protocol = DocStreamReceiver(response, d, doc_reader)
        response.deliverBody(protocol)
        if protocol.transport is not None and getAbort() is None:
            warnings.warn(
                'Using readBody with a transport that does not have an '
                'abortConnection method',
                category=DeprecationWarning,
                stacklevel=2)
        return d
    return read


def read_doc(doc_info, content):
    print doc_info, len(content)


def finish(args):
    print args
    reactor.stop()


def fetch(url, token, sync_id):
    headers = {'Authorization': ['Token %s' % token]}
    headers.update({'content-type': ['application/x-soledad-sync-get']})
    body = """[
{"ensure": false, "last_known_trans_id": "", "sync_id": "%s",
"last_known_generation": 0},
{"received": 0}
]""" % sync_id
    http = HTTPClient(pool=HTTPConnectionPool(reactor))
    d = http.request(url, 'POST', body, headers, build_body_reader(read_doc))
    d.addBoth(finish)


if __name__ == "__main__":
    assert len(sys.argv) == 4
    reactor.callWhenRunning(fetch, sys.argv[1], sys.argv[2], sys.argv[3])
    reactor.run()
