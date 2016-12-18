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
from routes.mapper import Mapper
from zope.interface import implementer

from twisted.cred import error
from twisted.cred.checkers import ICredentialsChecker
from twisted.cred.credentials import IUsernamePassword
from twisted.cred.credentials import UsernamePassword
from twisted.cred.portal import IRealm
from twisted.cred.portal import Portal
from twisted.web.iweb import ICredentialFactory
from twisted.web.resource import IResource

from leap.soledad.common import SHARED_DB_NAME
from leap.soledad.common.couch import couch_server
from leap.soledad.common.l2db import DBNAME_CONSTRAINTS
from leap.soledad.server.resource import SoledadResource
from leap.soledad.server.application import get_config


@implementer(IRealm)
class SoledadRealm(object):

    def requestAvatar(self, avatarId, mind, *interfaces):
        if IResource in interfaces:
            return (IResource, SoledadResource(avatarId), lambda: None)
        raise NotImplementedError()


@implementer(ICredentialsChecker)
class TokenChecker(object):

    credentialInterfaces = [IUsernamePassword]

    TOKENS_DB_PREFIX = "tokens_"
    TOKENS_DB_EXPIRE = 30 * 24 * 3600  # 30 days in seconds
    TOKENS_TYPE_KEY = "type"
    TOKENS_TYPE_DEF = "Token"
    TOKENS_USER_ID_KEY = "user_id"

    def __init__(self):
        config = get_config()
        self.couch_url = config['couch_url']

    def _tokens_dbname(self):
        dbname = self.TOKENS_DB_PREFIX + \
            str(int(time.time() / self.TOKENS_DB_EXPIRE))
        return dbname

    def requestAvatarId(self, credentials):
        uuid = credentials.username
        token = credentials.password
        with couch_server(self.couch_url) as server:
            # the tokens db rotates every 30 days, and the current db name is
            # "tokens_NNN", where NNN is the number of seconds since epoch
            # divide dby the rotate period in seconds. When rotating, old and
            # new tokens db coexist during a certain window of time and valid
            # tokens are replicated from the old db to the new one. See:
            # https://leap.se/code/issues/6785
            dbname = self._tokens_dbname()
            db = server[dbname]
        # lookup key is a hash of the token to prevent timing attacks.
        token = db.get(sha512(token).hexdigest())
        if token is None:
            return False
        # we compare uuid hashes to avoid possible timing attacks that
        # might exploit python's builtin comparison operator behaviour,
        # which fails immediatelly when non-matching bytes are found.
        couch_uuid_hash = sha512(token[self.TOKENS_USER_ID_KEY]).digest()
        req_uuid_hash = sha512(uuid).digest()
        if token[self.TOKENS_TYPE_KEY] != self.TOKENS_TYPE_DEF \
                or couch_uuid_hash != req_uuid_hash:
            return False
        return True


@implementer(ICredentialFactory)
class TokenCredentialFactory(object):

    scheme = 'token'

    def getChallenge(self, request):
        return {}

    def decode(self, response, request):
        try:
            creds = response.decode('base64')
        except binascii.Error:
            raise error.LoginFailed('Invalid credentials')

        creds = creds.split(b':', 1)
        if len(creds) == 2:
            return UsernamePassword(*creds)
        else:
            raise error.LoginFailed('Invalid credentials')


portal = Portal(SoledadRealm(), [TokenChecker()])
credentialFactory = TokenCredentialFactory()


class URLMapper(object):
    """
    Maps the URLs users can access.
    """

    def __init__(self):
        self._map = Mapper(controller_scan=None)
        self._connect_urls()
        self._map.create_regs()

    def match(self, path, method):
        environ = {'PATH_INFO': path, 'REQUEST_METHOD': method}
        return self._map.match(environ=environ)

    def _connect(self, pattern, http_methods):
        self._map.connect(
            None, pattern, http_methods=http_methods,
            conditions=dict(method=http_methods),
            requirements={'dbname': DBNAME_CONSTRAINTS})

    def _connect_urls(self):
        """
        Register the authorization info in the mapper using C{SHARED_DB_NAME}
        as the user's database name.

        This method sets up the following authorization rules:

            URL path                      | Authorized actions
            --------------------------------------------------
            /                             | GET
            /shared-db                    | GET
            /shared-db/docs               | -
            /shared-db/doc/{any_id}       | GET, PUT, DELETE
            /shared-db/sync-from/{source} | -
            /user-db                      | -
            /user-db/docs                 | -
            /user-db/doc/{id}             | -
            /user-db/sync-from/{source}   | GET, PUT, POST
        """
        # auth info for global resource
        self._connect('/', ['GET'])
        # auth info for shared-db database resource
        self._connect('/%s' % SHARED_DB_NAME, ['GET'])
        # auth info for shared-db doc resource
        self._connect('/%s/doc/{id:.*}' % SHARED_DB_NAME,
                      ['GET', 'PUT', 'DELETE'])
        # auth info for user-db sync resource
        self._connect('/user-{uuid}/sync-from/{source_replica_uid}',
                      ['GET', 'PUT', 'POST'])


@implementer(IResource)
class UnauthorizedResource(object):
    isLeaf = True

    def render(self, request):
        request.setResponseCode(401)
        if request.method == b'HEAD':
            return b''
        return b'Unauthorized'

    def getChildWithDefault(self, path, request):
        return self
