# -*- coding: utf-8 -*-
# _http.py
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
A twisted-based HTTP client that:

    - is pinned to a specific TLS certificate,
    - does token authentication using the Authorization header,
    - can do bandwidth throttling.
"""
import base64
import os
import sys

from twisted.internet import reactor
from twisted.protocols.policies import ThrottlingFactory
from twisted.protocols.policies import ThrottlingProtocol
from twisted.web.iweb import IAgent
from twisted.web.client import Agent as _Agent
from twisted.web.client import CookieAgent
from twisted.web.client import HTTPConnectionPool
from twisted.web.http_headers import Headers

from cookielib import CookieJar
from treq.client import HTTPClient as _HTTPClient
from zope.interface import implementer

from leap.common.http import getPolicyForHTTPS


__all__ = ['HTTPClient']


class HTTPClient(_HTTPClient):

    def __init__(self, uuid, token, cert_file):
        agent = Agent(uuid, token, cert_file)
        jar = CookieJar()
        self._agent = CookieAgent(agent, jar)
        super(self.__class__, self).__init__(self._agent)

    def set_token(self, token):
        self._agent.set_token(token)


class HTTPThrottlingProtocol(ThrottlingProtocol):

    def request(self, *args, **kwargs):
        return self.wrappedProtocol.request(*args, **kwargs)

    def throttleWrites(self):
        if hasattr(self, 'producer') and self.producer:
            self.producer.pauseProducing()

    def unthrottleWrites(self):
        if hasattr(self, 'producer') and self.producer:
            self.producer.resumeProducing()


class HTTPThrottlingFactory(ThrottlingFactory):

    protocol = HTTPThrottlingProtocol


class ThrottlingHTTPConnectionPool(HTTPConnectionPool):

    maxPersistentPerHost = 1          # throttling happens "host-wise"
    maxConnectionCount = sys.maxsize  # max number of concurrent connections
    readLimit = 1 * 10 ** 6           # max bytes we should read per second
    writeLimit = 1 * 10 ** 6          # max bytes we should write per second

    def _newConnection(self, key, endpoint):
        def quiescentCallback(protocol):
            self._putConnection(key, protocol)
        factory = self._factory(quiescentCallback, repr(endpoint))
        throttlingFactory = HTTPThrottlingFactory(
            factory,
            maxConnectionCount=self.maxConnectionCount,
            readLimit=self.readLimit,
            writeLimit=self.writeLimit)
        return endpoint.connect(throttlingFactory)


@implementer(IAgent)
class Agent(_Agent):

    def __init__(self, uuid, token, cert_file, throttling=False):
        self._uuid = uuid
        self._token = None
        self._creds = None
        self.set_token(token)
        factory = getPolicyForHTTPS(cert_file)
        pool = self._get_pool()
        _Agent.__init__(self, reactor, contextFactory=factory, pool=pool)

    def _get_pool(self):
        throttling = bool(os.environ.get('SOLEDAD_THROTTLING'))
        persistent = bool(os.environ.get('SOLEDAD_HTTP_PERSIST'))
        if throttling:
            klass = ThrottlingHTTPConnectionPool
        else:
            klass = HTTPConnectionPool
        return klass(reactor, persistent=persistent)

    def set_token(self, token):
        self._token = token
        self._creds = self._encoded_creds()

    def _encoded_creds(self):
        creds = '%s:%s' % (self._uuid, self._token)
        encoded = base64.b64encode(creds)
        return 'Token %s' % encoded

    def request(self, method, uri, headers=None, bodyProducer=None):
        # authenticate the request
        headers = headers or Headers()
        headers.addRawHeader('Authorization', self._creds)
        # perform the authenticated request
        return _Agent.request(
            self, method, uri, headers=headers, bodyProducer=bodyProducer)
