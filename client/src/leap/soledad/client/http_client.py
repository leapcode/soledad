# -*- coding: utf-8 -*-
# http_client.py
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


"""
Twisted HTTP/HTTPS client.
"""

import os

from zope.interface import implements

from OpenSSL.crypto import load_certificate
from OpenSSL.crypto import FILETYPE_PEM

from twisted.internet import reactor
from twisted.internet.ssl import ClientContextFactory
from twisted.internet.ssl import CertificateOptions
from twisted.internet.defer import succeed

from twisted.web.client import Agent
from twisted.web.client import HTTPConnectionPool
from twisted.web.client import readBody
from twisted.web.http_headers import Headers
from twisted.web.error import Error
from twisted.web.iweb import IBodyProducer


from leap.soledad.common.errors import InvalidAuthTokenError


#
# Setup a pool of connections
#

_pool = HTTPConnectionPool(reactor, persistent=True)
_pool.maxPersistentPerHost = 10
_agent = None

# if we ever want to trust the system's CAs, we should use an agent like this:
# from twisted.web.client import BrowserLikePolicyForHTTPS
# _agent = Agent(reactor, BrowserLikePolicyForHTTPS(), pool=_pool)


#
# SSL/TLS certificate configuration
#

def configure_certificate(cert_file):
    """
    Configure an agent that verifies server certificates against a CA cert
    file.

    :param cert_file: The path to the certificate file.
    :type cert_file: str
    """
    global _agent
    cert = _load_cert(cert_file)
    _agent = Agent(
        reactor,
        SoledadClientContextFactory(cert),
        pool=_pool)


def _load_cert(cert_file):
    """
    Load a X509 certificate from a file.

    :param cert_file: The path to the certificate file.
    :type cert_file: str

    :return: The X509 certificate.
    :rtype: OpenSSL.crypto.X509
    """
    if os.path.exists(cert_file):
        with open(cert_file) as f:
            data = f.read()
            return load_certificate(FILETYPE_PEM, data)


class SoledadClientContextFactory(ClientContextFactory):
    """
    A context factory that will verify the server's certificate against a
    given CA certificate.
    """

    def __init__(self, cacert):
        """
        Initialize the context factory.

        :param cacert: The CA certificate.
        :type cacert: OpenSSL.crypto.X509
        """
        self._cacert = cacert

    def getContext(self, hostname, port):
        opts = CertificateOptions(verify=True, caCerts=[self._cacert])
        return opts.getContext()


#
# HTTP request facilities
#

def _unauth_to_invalid_token_error(failure):
    """
    An errback to translate unauthorized errors to our own invalid token
    class.

    :param failure: The original failure.
    :type failure: twisted.python.failure.Failure

    :return: Either the original failure or an invalid auth token error.
    :rtype: twisted.python.failure.Failure
    """
    failure.trap(Error)
    if failure.getErrorMessage() == "401 Unauthorized":
        raise InvalidAuthTokenError
    return failure


class StringBodyProducer(object):
    """
    A producer that writes the body of a request to a consumer.
    """

    implements(IBodyProducer)

    def __init__(self, body):
        """
        Initialize the string produer.

        :param body: The body of the request.
        :type body: str
        """
        self.body = body
        self.length = len(body)

    def startProducing(self, consumer):
        """
        Write the body to the consumer.

        :param consumer: Any IConsumer provider.
        :type consumer: twisted.internet.interfaces.IConsumer

        :return: A successful deferred.
        :rtype: twisted.internet.defer.Deferred
        """
        consumer.write(self.body)
        return succeed(None)

    def pauseProducing(self):
        pass

    def stopProducing(self):
        pass


def httpRequest(url, method='GET', body=None, headers={}):
    """
    Perform an HTTP request.

    :param url: The URL for the request.
    :type url: str
    :param method: The HTTP method of the request.
    :type method: str
    :param body: The body of the request, if any.
    :type body: str
    :param headers: The headers of the request.
    :type headers: dict

    :return: A deferred that fires with the body of the request.
    :rtype: twisted.internet.defer.Deferred
    """
    if body:
        body = StringBodyProducer(body)
    d = _agent.request(
        method, url, headers=Headers(headers), bodyProducer=body)
    d.addCallbacks(readBody, _unauth_to_invalid_token_error)
    return d
