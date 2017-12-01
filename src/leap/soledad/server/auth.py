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
import os
import binascii
import time

from hashlib import sha512
from zope.interface import implementer

from twisted.cred import error
from twisted.cred.checkers import ICredentialsChecker
from twisted.cred.credentials import IUsernamePassword
from twisted.cred.credentials import IAnonymous
from twisted.cred.credentials import Anonymous
from twisted.cred.credentials import UsernamePassword
from twisted.cred.portal import IRealm
from twisted.cred.portal import Portal
from twisted.internet import defer
from twisted.web.iweb import ICredentialFactory
from twisted.web.resource import IResource

from leap.soledad.common.couch import couch_server
from leap.soledad.common.log import getLogger

from ._resource import PublicResource, AnonymousResource
from ._resource import LocalResource
from ._blobs import BlobsResource
from ._streaming_resource import StreamingResource
from ._config import get_config


log = getLogger(__name__)


def _update_with_defaults(conf):
    for k, v in get_config().items():
        conf.setdefault(k, v)


@implementer(IRealm)
class SoledadRealm(object):

    def __init__(self, sync_pool, conf={}):
        assert sync_pool is not None
        _update_with_defaults(conf)
        blobs = conf['blobs']
        concurrent_writes = conf['concurrent_blob_writes']
        blobs_resource = BlobsResource(
            "filesystem",
            conf['blobs_path'],
            concurrent_writes=concurrent_writes) if blobs else None
        streaming_resource = StreamingResource(
            "filesystem",
            conf['blobs_path'],
            concurrent_writes=concurrent_writes) if blobs else None
        self.anon_resource = AnonymousResource(
            enable_blobs=blobs)
        self.auth_resource = PublicResource(
            blobs_resource=blobs_resource,
            streaming_resource=streaming_resource,
            sync_pool=sync_pool)

    def requestAvatar(self, avatarId, mind, *interfaces):

        # Anonymous access
        if IAnonymous.providedBy(avatarId):
            return (IResource, self.anon_resource,
                    lambda: None)

        # Authenticated access
        else:
            if IResource in interfaces:
                return (IResource, self.auth_resource,
                        lambda: None)
        raise NotImplementedError()


@implementer(IRealm)
class LocalServicesRealm(object):

    def __init__(self):
        conf = get_config()
        self.anon_resource = AnonymousResource(
            enable_blobs=conf['blobs'])
        self.auth_resource = LocalResource()

    def requestAvatar(self, avatarId, mind, *interfaces):

        # Anonymous access
        if IAnonymous.providedBy(avatarId):
            return (IResource, self.anon_resource,
                    lambda: None)

        # Authenticated access
        else:
            if IResource in interfaces:
                return (IResource, self.auth_resource,
                        lambda: None)
        raise NotImplementedError()


@implementer(ICredentialsChecker)
class FileTokenChecker(object):
    credentialInterfaces = [IUsernamePassword, IAnonymous]

    def __init__(self, conf={}):
        # conf parameter is only used during tests
        _update_with_defaults(conf)
        self._trusted_services_tokens = {}
        self._tokens_file_path = conf['services_tokens_file']
        self._reload_tokens()

    def _reload_tokens(self):
        if not os.path.isfile(self._tokens_file_path):
            log.warn("No local token auth file at %s" % self._tokens_file_path)
            return
        with open(self._tokens_file_path) as tokens_file:
            for line in tokens_file.readlines():
                line = line.strip()
                if not line.startswith('#'):
                    service, token = line.split(':')
                    log.info("Loaded credentials for service: %s" % service)
                    self._trusted_services_tokens[service] = token

    def requestAvatarId(self, credentials):
        if IAnonymous.providedBy(credentials):
            return defer.succeed(Anonymous())

        service = credentials.username
        token = credentials.password

        # TODO: Use constant time comparison
        if self._trusted_services_tokens[service] != token:
            return defer.fail(error.UnauthorizedLogin())

        return defer.succeed(service)


@implementer(ICredentialsChecker)
class CouchDBTokenChecker(object):

    credentialInterfaces = [IUsernamePassword, IAnonymous]

    TOKENS_DB_PREFIX = "tokens_"
    TOKENS_DB_EXPIRE = 30 * 24 * 3600  # 30 days in seconds
    TOKENS_TYPE_KEY = "type"
    TOKENS_TYPE_DEF = "Token"
    TOKENS_USER_ID_KEY = "user_id"

    def __init__(self):
        self._couch_url = get_config().get('couch_url')

    def _get_server(self):
        return couch_server(self._couch_url)

    def _tokens_dbname(self):
        # the tokens db rotates every 30 days, and the current db name is
        # "tokens_NNN", where NNN is the number of seconds since epoch
        # divide dby the rotate period in seconds. When rotating, old and
        # new tokens db coexist during a certain window of time and valid
        # tokens are replicated from the old db to the new one. See:
        # https://leap.se/code/issues/6785
        dbname = self.TOKENS_DB_PREFIX + \
            str(int(time.time() / self.TOKENS_DB_EXPIRE))
        return dbname

    def _tokens_db(self):
        dbname = self._tokens_dbname()

        # TODO -- leaking abstraction here: this module shouldn't need
        # to known anything about the context manager. hide that in the couch
        # module
        with self._get_server() as server:
            db = server[dbname]
        return db

    def requestAvatarId(self, credentials):
        if IAnonymous.providedBy(credentials):
            return defer.succeed(Anonymous())

        uuid = credentials.username
        token = credentials.password

        # lookup key is a hash of the token to prevent timing attacks.
        # TODO cache the tokens already!

        db = self._tokens_db()
        token = db.get(sha512(token).hexdigest())
        if token is None:
            return defer.fail(error.UnauthorizedLogin())

        # TODO -- use cryptography constant time builtin comparison.
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


def publicPortal(sync_pool):
    database_checker = CouchDBTokenChecker()
    realm = SoledadRealm(sync_pool=sync_pool)
    auth_checkers = [database_checker]
    return Portal(realm, auth_checkers)


def localPortal():
    file_checker = FileTokenChecker()
    realm = LocalServicesRealm()
    auth_checkers = [file_checker]
    return Portal(realm, auth_checkers)


credentialFactory = TokenCredentialFactory()
