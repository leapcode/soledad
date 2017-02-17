# -*- coding: utf-8 -*-
# session.py
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
Twisted resource containing an authenticated Soledad session.
"""
from zope.interface import implementer

from twisted.cred.credentials import Anonymous
from twisted.cred import error
from twisted.python import log
from twisted.web import util
from twisted.web._auth import wrapper
from twisted.web.guard import HTTPAuthSessionWrapper
from twisted.web.resource import ErrorPage
from twisted.web.resource import IResource

from leap.soledad.server.auth import credentialFactory
from leap.soledad.server.url_mapper import URLMapper


@implementer(IResource)
class UnauthorizedResource(wrapper.UnauthorizedResource):
    isLeaf = True

    def __init__(self):
        pass

    def render(self, request):
        request.setResponseCode(401)
        if request.method == b'HEAD':
            return b''
        return b'Unauthorized'

    def getChildWithDefault(self, path, request):
        return self


@implementer(IResource)
class SoledadSession(HTTPAuthSessionWrapper):

    def __init__(self, portal):
        self._mapper = URLMapper()
        self._portal = portal
        self._credentialFactory = credentialFactory
        # expected by the contract of the parent class
        self._credentialFactories = [credentialFactory]

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
        # check whether the path of the request exists in the app
        match = self._matchPath(request)
        if not match:
            return UnauthorizedResource()

        # get authorization header or fail
        header = request.getHeader(b'authorization')
        if not header:
            return util.DeferredResource(self._login(Anonymous()))

        # parse the authorization header
        auth_data = self._parseHeader(header)
        if not auth_data:
            return UnauthorizedResource()

        # decode the credentials from the parsed header
        try:
            credentials = self._credentialFactory.decode(auth_data, request)
        except error.LoginFailed:
            return UnauthorizedResource()
        except:
            # If you port this to the newer log facility, be aware that
            # the tests rely on the error to be logged.
            log.err(None, "Unexpected failure from credentials factory")
            return ErrorPage(500, None, None)

        # make sure the uuid given in path corresponds to the one given in
        # the credentials
        request_uuid = match.get('uuid')
        if request_uuid and request_uuid != credentials.username:
            return ErrorPage(500, None, None)

        # if all checks pass, try to login with credentials
        return util.DeferredResource(self._login(credentials))
