# -*- coding: utf-8 -*-
# application.py
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

from leap.soledad.server import SoledadApp
from leap.soledad.server.auth import SoledadTokenAuthMiddleware
from leap.soledad.server.gzip_middleware import GzipMiddleware
from leap.soledad.server.config import load_configuration
from leap.soledad.common.backend import SoledadBackend
from leap.soledad.common.couch.state import CouchServerState


# ----------------------------------------------------------------------------
# Run as Twisted WSGI Resource
# ----------------------------------------------------------------------------

def _load_config():
    conf = load_configuration('/etc/soledad/soledad-server.conf')
    return conf['soledad-server']


def _get_couch_state():
    conf = _load_config()
    state = CouchServerState(conf['couch_url'], create_cmd=conf['create_cmd'],
                             check_schema_versions=True)
    SoledadBackend.BATCH_SUPPORT = conf.get('batching', False)
    return state


_couch_state = _get_couch_state()

# a WSGI application that may be used by `twistd -web`
wsgi_application = GzipMiddleware(
    SoledadTokenAuthMiddleware(SoledadApp(_couch_state)))
