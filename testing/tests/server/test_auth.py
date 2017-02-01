# -*- coding: utf-8 -*-
# test_auth.py
# Copyright (C) 2013 LEAP
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
Tests for auth pieces.
"""
import collections

from twisted.cred.credentials import UsernamePassword
from twisted.cred.error import UnauthorizedLogin
from twisted.internet.defer import inlineCallbacks
from twisted.trial import unittest
from twisted.web.resource import IResource

from leap.soledad.server.auth import SoledadRealm
from leap.soledad.server.auth import TokenChecker
from leap.soledad.server.auth import TokenCredentialFactory
from leap.soledad.server.resource import SoledadResource


class SoledadRealmTestCase(unittest.TestCase):

    def test_returned_resource(self):
        realm = SoledadRealm()
        iface, avatar, logout = realm.requestAvatar('any', None, IResource)
        self.assertIsInstance(avatar, SoledadResource)
        self.assertIsNone(logout())


class DummyServer(object):
    """
    I fake the `couchdb.client.Server` GET api and always return the token
    given on my creation.
    """

    def __init__(self, token):
        self._token = token

    def get(self, _):
        return self._token


class TokenCheckerTestCase(unittest.TestCase):

    @inlineCallbacks
    def test_good_creds(self):
        # set up a dummy server which always return a *valid* token document
        token = {'user_id': 'user', 'type': 'Token'}
        server = collections.defaultdict(lambda: DummyServer(token))
        # setup the checker with the custom server
        checker = TokenChecker(server=server)
        # assert the checker *can* verify the creds
        creds = UsernamePassword('user', 'pass')
        avatarId = yield checker.requestAvatarId(creds)
        self.assertEqual('user', avatarId)

    @inlineCallbacks
    def test_bad_creds(self):
        # set up a dummy server which always return an *invalid* token document
        token = None
        server = collections.defaultdict(lambda: DummyServer(token))
        # setup the checker with the custom server
        checker = TokenChecker(server=server)
        # assert the checker *cannot* verify the creds
        creds = UsernamePassword('user', '')
        with self.assertRaises(UnauthorizedLogin):
            yield checker.requestAvatarId(creds)


from twisted.web.test import test_httpauth


class TokenCredentialFactoryTestcase(
        test_httpauth.RequestMixin, test_httpauth.BasicAuthTestsMixin,
        unittest.TestCase):

    def setUp(self):
        test_httpauth.BasicAuthTestsMixin.setUp(self)
        self.credentialFactory = TokenCredentialFactory()
