# -*- coding: utf-8 -*-
# session.py
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
Twisted resource containing an authenticated Soledad session.
"""
from zope.interface import implementer

from twisted.cred import error
from twisted.python import log
from twisted.python.components import registerAdapter
from twisted.web import util
from twisted.web.guard import HTTPAuthSessionWrapper
from twisted.web.resource import ErrorPage
from twisted.web.resource import IResource
from twisted.web.server import Session
from zope.interface import Interface
from zope.interface import Attribute

from leap.soledad.server.auth import URLMapper
from leap.soledad.server.auth import portal
from leap.soledad.server.auth import credentialFactory
from leap.soledad.server.auth import UnauthorizedResource
from leap.soledad.server.resource import SoledadResource


class ISessionData(Interface):
    username = Attribute('An uuid.')
    password = Attribute('A token.')


@implementer(ISessionData)
class SessionData(object):
    def __init__(self, session):
        self.username = None
        self.password = None


registerAdapter(SessionData, Session, ISessionData)


def _sessionData(request):
    session = request.getSession()
    data = ISessionData(session)
    return data


@implementer(IResource)
class SoledadSession(HTTPAuthSessionWrapper):

    def __init__(self):
        self._mapper = URLMapper()
        self._portal = portal
        self._credentialFactory = credentialFactory

    def _matchPath(self, request):
        match = self._mapper.match(request.path, request.method)
        return match

    def _parseHeader(self, header):
        elements = header.split(b' ')
        scheme = elements[0].lower()
        if scheme == self._credentialFactory.scheme:
            return (b' '.join(elements[1:]))
        return None

    def _authorizedResource(self, request):
        match = self._matchPath(request)
        if not match:
            return UnauthorizedResource()

        header = request.getHeader(b'authorization')
        if not header:
            return UnauthorizedResource()

        auth_data = self._parseHeader(header)
        if not auth_data:
            return UnauthorizedResource()

        try:
            credentials = self._credentialFactory.decode(auth_data, request)
        except error.LoginFailed:
            return UnauthorizedResource()
        except:
            log.err(None, "Unexpected failure from credentials factory")
            return ErrorPage(500, None, None)

        request_uuid = match.get('uuid')
        if request_uuid and request_uuid != credentials.username:
            return ErrorPage(500, None, None)

        # eventually return a cached resouce
        sessionData = _sessionData(request)
        if sessionData.username == credentials.username \
                and sessionData.password == credentials.password:
            return SoledadResource()

        return util.DeferredResource(self._login(credentials, sessionData))

    def _login(self, credentials, sessionData):

        def _cacheSessionData(res):
            sessionData.username = credentials.username
            sessionData.password = credentials.password
            return res

        d = self._portal.login(credentials, None, IResource)
        d.addCallback(_cacheSessionData)
        d.addCallbacks(self._loginSucceeded, self._loginFailed)
        return d
