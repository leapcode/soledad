# -*- coding: utf-8 -*-
# http_target.py
# Copyright (C) 2015 LEAP
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
import warnings
import json
from u1db import errors
from u1db.remote import http_errors
from twisted.internet import defer
from twisted.web.client import _ReadBodyProtocol
from twisted.web.client import PartialDownloadError
from twisted.web._newclient import ResponseDone
from twisted.web._newclient import PotentialDataLoss


# we want to make sure that HTTP errors will raise appropriate u1db errors,
# that is, fire errbacks with the appropriate failures, in the context of
# twisted. Because of that, we redefine the http body reader used by the HTTP
# client below.

class ReadBodyProtocol(_ReadBodyProtocol):

    def __init__(self, response, deferred):
        """
        Initialize the protocol, additionally storing the response headers.
        """
        _ReadBodyProtocol.__init__(
            self, response.code, response.phrase, deferred)
        self.headers = response.headers

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

            body = b''.join(self.dataBuffer)

            # ---8<--- snippet from u1db.remote.http_client
            if self.status in (200, 201):
                self.deferred.callback(body)
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
                                     b''.join(self.dataBuffer)))
        else:
            self.deferred.errback(reason)


def readBody(response):
    """
    Get the body of an L{IResponse} and return it as a byte string.

    This is a helper function for clients that don't want to incrementally
    receive the body of an HTTP response.

    @param response: The HTTP response for which the body will be read.
    @type response: L{IResponse} provider

    @return: A L{Deferred} which will fire with the body of the response.
        Cancelling it will close the connection to the server immediately.
    """
    def cancel(deferred):
        """
        Cancel a L{readBody} call, close the connection to the HTTP server
        immediately, if it is still open.

        @param deferred: The cancelled L{defer.Deferred}.
        """
        abort = getAbort()
        if abort is not None:
            abort()

    d = defer.Deferred(cancel)
    protocol = ReadBodyProtocol(response, d)

    def getAbort():
        return getattr(protocol.transport, 'abortConnection', None)

    response.deliverBody(protocol)

    if protocol.transport is not None and getAbort() is None:
        warnings.warn(
            'Using readBody with a transport that does not have an '
            'abortConnection method',
            category=DeprecationWarning,
            stacklevel=2)

    return d


class RequestBody(object):

    def __init__(self, **header_dict):
        self.headers = header_dict
        self.entries = []

    def insert_info(self, **entry_dict):
        entry = json.dumps(entry_dict)
        self.entries.append(entry)
        return len(entry)

    def remove(self, number=1):
        entries = [self.entries.pop(0) for i in xrange(number)]
        return self.entries_to_str(entries)

    def __str__(self):
        return self.entries_to_str(self.entries)

    def __len__(self):
        return len(self.entries)

    def entries_to_str(self, entries=None):
        data = '[\r\n' + json.dumps(self.headers)
        data += ''.join(',\r\n' + entry for entry in entries)
        return data + '\r\n]'
