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

from ._blobs import blobs_resource
from ._server_info import ServerInfo
from ._wsgi import get_sync_resource


__all__ = ['SoledadResource']


class SoledadResource(Resource):
    """
    This is a dummy twisted resource, used only to allow different entry points
    for the Soledad Server.
    """

    def __init__(self, conf, sync_pool=None):
        Resource.__init__(self)

        blobs_enabled = conf['soledad-server']['blobs']

        # requests to / return server information
        server_info = ServerInfo(blobs_enabled)
        self.putChild('', server_info)

        # requests to /blobs will serve blobs if enabled
        if blobs_enabled:
            self.putChild('blobs', blobs_resource)

        # other requests are routed to legacy sync resource
        self._sync_resource = get_sync_resource(sync_pool)

    def getChild(self, path, request):
        """
        Route requests to legacy WSGI sync resource dynamically.
        """
        request.postpath.insert(0, request.prepath.pop())
        return self._sync_resource
