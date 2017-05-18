# -*- coding: utf-8 -*-
# resource.py
# Copyright (C) 2016 LEAP
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
A twisted resource that serves the Soledad Server.
"""
from twisted.web.resource import Resource

from ._server_info import ServerInfo
from ._incoming import IncomingResource
from ._wsgi import get_sync_resource


__all__ = ['SoledadResource', 'SoledadAnonResource']


class _Robots(Resource):
    def render_GET(self, request):
        return (
            'User-agent: *\n'
            'Disallow: /\n'
            '# you are not a robot, are you???')


class SoledadAnonResource(Resource):

    """
    The parts of Soledad Server that unauthenticated users can see.
    This is nice because this means that a non-authenticated user will get 404
    for anything that is not in this minimal resource tree.
    """

    def __init__(self, enable_blobs=False):
        Resource.__init__(self)
        server_info = ServerInfo(enable_blobs)
        self.putChild('', server_info)
        self.putChild('robots.txt', _Robots())


class SoledadResource(Resource):
    """
    This is a dummy twisted resource, used only to allow different entry points
    for the Soledad Server.
    """

    def __init__(self, blobs_resource=None, sync_pool=None):
        """
        Initialize the Soledad resource.

        :param blobs_resource: a resource to serve blobs, if enabled.
        :type blobs_resource: _blobs.BlobsResource

        :param sync_pool: A pool to pass to the WSGI sync resource.
        :type sync_pool: twisted.python.threadpool.ThreadPool
        """
        Resource.__init__(self)

        # requests to / return server information
        server_info = ServerInfo(bool(blobs_resource))
        self.putChild('', server_info)

        # requests to /blobs will serve blobs if enabled
        if blobs_resource:
            self.putChild('blobs', blobs_resource)

        # requests to /incoming goes into IncomingResource
        self.putChild('incoming', IncomingResource())

        # other requests are routed to legacy sync resource
        self._sync_resource = get_sync_resource(sync_pool)

    def getChild(self, path, request):
        """
        Route requests to legacy WSGI sync resource dynamically.
        """
        request.postpath.insert(0, request.prepath.pop())
        return self._sync_resource
