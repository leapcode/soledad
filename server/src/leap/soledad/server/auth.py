# -*- coding: utf-8 -*-
# auth.py
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
Twisted http token auth.
"""
import binascii
import time

from hashlib import sha512
from zope.interface import implementer

from twisted.cred import error
from twisted.cred.checkers import ICredentialsChecker
from twisted.cred.credentials import IUsernamePassword
from twisted.cred.credentials import UsernamePassword
from twisted.cred.portal import IRealm
from twisted.cred.portal import Portal
from twisted.internet import defer
from twisted.web.iweb import ICredentialFactory
from twisted.web.resource import IResource

from leap.soledad.common.couch import couch_server
from leap.soledad.server.resource import SoledadResource
from leap.soledad.server.application import get_config


@implementer(IRealm)
class SoledadRealm(object):

    def requestAvatar(self, avatarId, mind, *interfaces):
        if IResource in interfaces:
            return (IResource, SoledadResource(), lambda: None)
        raise NotImplementedError()


@implementer(ICredentialsChecker)
class TokenChecker(object):

    credentialInterfaces = [IUsernamePassword]

    TOKENS_DB_PREFIX = "tokens_"
    TOKENS_DB_EXPIRE = 30 * 24 * 3600  # 30 days in seconds
    TOKENS_TYPE_KEY = "type"
    TOKENS_TYPE_DEF = "Token"
    TOKENS_USER_ID_KEY = "user_id"

    def __init__(self, server=None):
        if server is None:
            config = get_config()
            couch_url = config['couch_url']
            server = couch_server(couch_url)
        self._server = server
        self._dbs = {}

    def _tokens_dbname(self):
        dbname = self.TOKENS_DB_PREFIX + \
            str(int(time.time() / self.TOKENS_DB_EXPIRE))
        return dbname

    def _get_db(self, dbname):
        if dbname not in self._dbs:
            self._dbs[dbname] = self._server[dbname]
        return self._dbs[dbname]

    def _tokens_db(self):
        # the tokens db rotates every 30 days, and the current db name is
        # "tokens_NNN", where NNN is the number of seconds since epoch
        # divide dby the rotate period in seconds. When rotating, old and
        # new tokens db coexist during a certain window of time and valid
        # tokens are replicated from the old db to the new one. See:
        # https://leap.se/code/issues/6785
        dbname = self._tokens_dbname()
        db = self._get_db(dbname)
        return db

    def requestAvatarId(self, credentials):
        uuid = credentials.username
        token = credentials.password

        # lookup key is a hash of the token to prevent timing attacks.
        db = self._tokens_db()
        token = db.get(sha512(token).hexdigest())
        if token is None:
            return defer.fail(error.UnauthorizedLogin())

        # we compare uuid hashes to avoid possible timing attacks that
        # might exploit python's builtin comparison operator behaviour,
        # which fails immediatelly when non-matching bytes are found.
        couch_uuid_hash = sha512(token[self.TOKENS_USER_ID_KEY]).digest()
        req_uuid_hash = sha512(uuid).digest()
        if token[self.TOKENS_TYPE_KEY] != self.TOKENS_TYPE_DEF \
                or couch_uuid_hash != req_uuid_hash:
            return defer.fail(error.UnauthorizedLogin())

        return defer.succeed(uuid)


@implementer(ICredentialFactory)
class TokenCredentialFactory(object):

    scheme = 'token'

    def getChallenge(self, request):
        return {}

    def decode(self, response, request):
        try:
            creds = binascii.a2b_base64(response + b'===')
        except binascii.Error:
            raise error.LoginFailed('Invalid credentials')

        creds = creds.split(b':', 1)
        if len(creds) == 2:
            return UsernamePassword(*creds)
        else:
            raise error.LoginFailed('Invalid credentials')


get_portal = lambda: Portal(SoledadRealm(), [TokenChecker()])
credentialFactory = TokenCredentialFactory()
