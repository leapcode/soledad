# -*- coding: utf-8 -*-
# test_session.py
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
Tests for server session entrypoint.
"""
from twisted.trial import unittest

from twisted.cred import portal
from twisted.cred.checkers import InMemoryUsernamePasswordDatabaseDontUse
from twisted.cred.credentials import IUsernamePassword
from twisted.web.resource import getChildForRequest
from twisted.web.static import Data
from twisted.web.test.requesthelper import DummyRequest
from twisted.web.test.test_httpauth import b64encode
from twisted.web.test.test_httpauth import Realm
from twisted.web._auth.wrapper import UnauthorizedResource

from leap.soledad.server.session import SoledadSession


class SoledadSessionTestCase(unittest.TestCase):
    """
    Tests adapted from for
    L{twisted.web.test.test_httpauth.HTTPAuthSessionWrapper}.
    """

    def makeRequest(self, *args, **kwargs):
        request = DummyRequest(*args, **kwargs)
        request.path = '/'
        return request

    def setUp(self):
        self.username = b'foo bar'
        self.password = b'bar baz'
        self.avatarContent = b"contents of the avatar resource itself"
        self.childName = b"foo-child"
        self.childContent = b"contents of the foo child of the avatar"
        self.checker = InMemoryUsernamePasswordDatabaseDontUse()
        self.checker.addUser(self.username, self.password)
        self.avatar = Data(self.avatarContent, 'text/plain')
        self.avatar.putChild(
            self.childName, Data(self.childContent, 'text/plain'))
        self.avatars = {self.username: self.avatar}
        self.realm = Realm(self.avatars.get)
        self.portal = portal.Portal(self.realm, [self.checker])
        self.wrapper = SoledadSession(self.portal)

    def _authorizedTokenLogin(self, request):
        authorization = b64encode(
            self.username + b':' + self.password)
        request.requestHeaders.addRawHeader(b'authorization',
                                            b'Token ' + authorization)
        return getChildForRequest(self.wrapper, request)

    def test_getChildWithDefault(self):
        request = self.makeRequest([self.childName])
        child = getChildForRequest(self.wrapper, request)
        d = request.notifyFinish()

        def cbFinished(result):
            self.assertEqual(request.responseCode, 401)

        d.addCallback(cbFinished)
        request.render(child)
        return d

    def _invalidAuthorizationTest(self, response):
        request = self.makeRequest([self.childName])
        request.requestHeaders.addRawHeader(b'authorization', response)
        child = getChildForRequest(self.wrapper, request)
        d = request.notifyFinish()

        def cbFinished(result):
            self.assertEqual(request.responseCode, 401)

        d.addCallback(cbFinished)
        request.render(child)
        return d

    def test_getChildWithDefaultUnauthorizedUser(self):
        return self._invalidAuthorizationTest(
            b'Basic ' + b64encode(b'foo:bar'))

    def test_getChildWithDefaultUnauthorizedPassword(self):
        return self._invalidAuthorizationTest(
            b'Basic ' + b64encode(self.username + b':bar'))

    def test_getChildWithDefaultUnrecognizedScheme(self):
        return self._invalidAuthorizationTest(b'Quux foo bar baz')

    def test_getChildWithDefaultAuthorized(self):
        request = self.makeRequest([self.childName])
        child = self._authorizedTokenLogin(request)
        d = request.notifyFinish()

        def cbFinished(ignored):
            self.assertEqual(request.written, [self.childContent])

        d.addCallback(cbFinished)
        request.render(child)
        return d

    def test_renderAuthorized(self):
        # Request it exactly, not any of its children.
        request = self.makeRequest([])
        child = self._authorizedTokenLogin(request)
        d = request.notifyFinish()

        def cbFinished(ignored):
            self.assertEqual(request.written, [self.avatarContent])

        d.addCallback(cbFinished)
        request.render(child)
        return d

    def test_decodeRaises(self):
        request = self.makeRequest([self.childName])
        request.requestHeaders.addRawHeader(b'authorization',
                                            b'Token decode should fail')
        child = getChildForRequest(self.wrapper, request)
        self.assertIsInstance(child, UnauthorizedResource)

    def test_parseResponse(self):
        basicAuthorization = b'Basic abcdef123456'
        self.assertEqual(
            self.wrapper._parseHeader(basicAuthorization),
            None)
        tokenAuthorization = b'Token abcdef123456'
        self.assertEqual(
            self.wrapper._parseHeader(tokenAuthorization),
            b'abcdef123456')

    def test_unexpectedDecodeError(self):

        class UnexpectedException(Exception):
            pass

        class BadFactory(object):
            scheme = b'bad'

            def getChallenge(self, client):
                return {}

            def decode(self, response, request):
                print("decode raised")
                raise UnexpectedException()

        self.wrapper._credentialFactory = BadFactory()
        request = self.makeRequest([self.childName])
        request.requestHeaders.addRawHeader(b'authorization', b'Bad abc')
        child = getChildForRequest(self.wrapper, request)
        request.render(child)
        self.assertEqual(request.responseCode, 500)
        errors = self.flushLoggedErrors(UnexpectedException)
        self.assertEqual(len(errors), 1)

    def test_unexpectedLoginError(self):
        class UnexpectedException(Exception):
            pass

        class BrokenChecker(object):
            credentialInterfaces = (IUsernamePassword,)

            def requestAvatarId(self, credentials):
                raise UnexpectedException()

        self.portal.registerChecker(BrokenChecker())
        request = self.makeRequest([self.childName])
        child = self._authorizedTokenLogin(request)
        request.render(child)
        self.assertEqual(request.responseCode, 500)
        self.assertEqual(len(self.flushLoggedErrors(UnexpectedException)), 1)

    def test_cantAccessOtherUserPathByDefault(self):
        request = self.makeRequest([])
        # valid url_mapper path, but for another user
        request.path = '/blobs/another-user/'
        child = self._authorizedTokenLogin(request)

        request.render(child)
        self.assertEqual(request.responseCode, 500)
