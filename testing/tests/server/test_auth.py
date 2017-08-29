# -*- coding: utf-8 -*-
# test_auth.py
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
Tests for auth pieces.
"""
import os
import collections
import pytest

from contextlib import contextmanager

from twisted.cred.credentials import UsernamePassword
from twisted.cred.error import UnauthorizedLogin
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks
from twisted.trial import unittest
from twisted.web.resource import IResource
from twisted.web.test import test_httpauth

import leap.soledad.server.auth as auth_module
from leap.soledad.server.auth import SoledadRealm
from leap.soledad.server.auth import CouchDBTokenChecker
from leap.soledad.server.auth import FileTokenChecker
from leap.soledad.server.auth import TokenCredentialFactory
from leap.soledad.server._resource import PublicResource


class SoledadRealmTestCase(unittest.TestCase):

    def test_returned_resource(self):
        # we have to pass a pool to the realm , otherwise tests will hang
        conf = {'blobs': False}
        pool = reactor.getThreadPool()
        realm = SoledadRealm(conf=conf, sync_pool=pool)
        iface, avatar, logout = realm.requestAvatar('any', None, IResource)
        self.assertIsInstance(avatar, PublicResource)
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


@contextmanager
def dummy_server(token):
    yield collections.defaultdict(lambda: DummyServer(token))


class CouchDBTokenCheckerTestCase(unittest.TestCase):

    @inlineCallbacks
    def test_good_creds(self):
        # set up a dummy server which always return a *valid* token document
        token = {'user_id': 'user', 'type': 'Token'}
        server = dummy_server(token)
        # setup the checker with the custom server
        checker = CouchDBTokenChecker()
        auth_module.couch_server = lambda url: server
        # assert the checker *can* verify the creds
        creds = UsernamePassword('user', 'pass')
        avatarId = yield checker.requestAvatarId(creds)
        self.assertEqual('user', avatarId)

    @inlineCallbacks
    def test_bad_creds(self):
        # set up a dummy server which always return an *invalid* token document
        token = None
        server = dummy_server(token)
        # setup the checker with the custom server
        checker = CouchDBTokenChecker()
        auth_module.couch_server = lambda url: server
        # assert the checker *cannot* verify the creds
        creds = UsernamePassword('user', '')
        with self.assertRaises(UnauthorizedLogin):
            yield checker.requestAvatarId(creds)


class FileTokenCheckerTestCase(unittest.TestCase):

    @inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_good_creds(self):
        auth_file_path = os.path.join(self.tempdir, 'auth.file')
        with open(auth_file_path, 'w') as tempfile:
            tempfile.write('goodservice:goodtoken')
        # setup the checker with the auth tokens file
        conf = {'services_tokens_file': auth_file_path}
        checker = FileTokenChecker(conf)
        # assert the checker *can* verify the creds
        creds = UsernamePassword('goodservice', 'goodtoken')
        avatarId = yield checker.requestAvatarId(creds)
        self.assertEqual('goodservice', avatarId)

    @inlineCallbacks
    @pytest.mark.usefixtures("method_tmpdir")
    def test_bad_creds(self):
        auth_file_path = os.path.join(self.tempdir, 'auth.file')
        with open(auth_file_path, 'w') as tempfile:
            tempfile.write('service:token')
        # setup the checker with the auth tokens file
        conf = {'services_tokens_file': auth_file_path}
        checker = FileTokenChecker(conf)
        # assert the checker *cannot* verify the creds
        creds = UsernamePassword('service', 'wrongtoken')
        with self.assertRaises(UnauthorizedLogin):
            yield checker.requestAvatarId(creds)


class TokenCredentialFactoryTestcase(
        test_httpauth.RequestMixin, test_httpauth.BasicAuthTestsMixin,
        unittest.TestCase):

    def setUp(self):
        test_httpauth.BasicAuthTestsMixin.setUp(self)
        self.credentialFactory = TokenCredentialFactory()
