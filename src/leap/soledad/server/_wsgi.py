# -*- coding: utf-8 -*-
# _wsgi.py
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
A WSGI application that serves Soledad synchronization.
"""
from twisted.internet import reactor
from twisted.web.wsgi import WSGIResource

from leap.soledad.server._config import get_config
from leap.soledad.server import SoledadApp
from leap.soledad.server.gzip_middleware import GzipMiddleware
from leap.soledad.common.backend import SoledadBackend
from leap.soledad.common.couch.state import CouchServerState


__all__ = ['get_sync_resource']


def _get_couch_state(conf):
    state = CouchServerState(conf['couch_url'], create_cmd=conf['create_cmd'])
    SoledadBackend.BATCH_SUPPORT = conf.get('batching', False)
    return state


def get_sync_resource(pool):
    conf = get_config()
    state = _get_couch_state(conf)
    app = SoledadApp(state)
    wsgi_app = GzipMiddleware(app)
    return WSGIResource(reactor, pool, wsgi_app)
