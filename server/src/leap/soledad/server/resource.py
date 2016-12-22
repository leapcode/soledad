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
from twisted.web.wsgi import WSGIResource
from twisted.internet import reactor
from twisted.python import threadpool

from leap.soledad.server.application import wsgi_application


__all__ = ['SoledadResource']


# setup a wsgi resource with its own threadpool
pool = threadpool.ThreadPool()
reactor.callWhenRunning(pool.start)
reactor.addSystemEventTrigger('after', 'shutdown', pool.stop)
wsgi_resource = WSGIResource(reactor, pool, wsgi_application)


class SoledadResource(Resource):
    """
    This is a dummy twisted resource, used only to allow different entry points
    for the Soledad Server.
    """

    def __init__(self):
        self.children = {'': wsgi_resource}

    def getChild(self, path, request):
        # for now, just "rewind" the path and serve the wsgi resource for all
        # requests. In the future, we might look into the request path to
        # decide which child resources should serve each request.
        request.postpath.insert(0, request.prepath.pop())
        return self.children['']
