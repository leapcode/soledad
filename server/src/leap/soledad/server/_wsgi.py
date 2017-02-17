# -*- coding: utf-8 -*-
# application.py
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

from leap.soledad.server import SoledadApp
from leap.soledad.server.gzip_middleware import GzipMiddleware
from leap.soledad.common.backend import SoledadBackend
from leap.soledad.common.couch.state import CouchServerState
from leap.soledad.common.log import getLogger

from twisted.logger import Logger
log = Logger()

__all__ = ['init_couch_state', 'get_sync_resource']


def _get_couch_state(conf):
    state = CouchServerState(conf['couch_url'], create_cmd=conf['create_cmd'],
                             check_schema_versions=True)
    SoledadBackend.BATCH_SUPPORT = conf.get('batching', False)
    return state


_app = SoledadApp(None)  # delay state init
wsgi_application = GzipMiddleware(_app)


# During its initialization, the couch state verifies if all user databases
# contain a config document with the correct couch schema version stored, and
# will log an error and raise an exception if that is not the case.
#
# If this verification made too early (i.e.  before the reactor has started and
# the twistd web logging facilities have been setup), the logging will not
# work.  Because of that, we delay couch state initialization until the reactor
# is running.

def init_couch_state(conf):
    try:
        _app.state = _get_couch_state(conf)
    except Exception as e:
        logger = getLogger()
        logger.error(str(e))
        reactor.stop()


def get_sync_resource(pool):
    return WSGIResource(reactor, pool, wsgi_application)
