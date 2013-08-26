# -*- coding: utf-8 -*-
# server.py
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
A U1DB server that stores data using CouchDB as its persistence layer.

This should be run with:
    twistd -n web --wsgi=leap.soledad_server.application --port=2424
"""

import configparser

from u1db.remote import http_app


# Keep OpenSSL's tsafe before importing Twisted submodules so we can put
# it back if Twisted==12.0.0 messes with it.
from OpenSSL import tsafe
old_tsafe = tsafe

from twisted.web.wsgi import WSGIResource
from twisted.internet import reactor
from twisted import version
if version.base() == "12.0.0":
    # Put OpenSSL's tsafe back into place. This can probably be removed if we
    # come to use Twisted>=12.3.0.
    import sys
    sys.modules['OpenSSL.tsafe'] = old_tsafe


from leap.soledad.server.auth import SoledadTokenAuthMiddleware
from leap.soledad.common.couch import CouchServerState


#-----------------------------------------------------------------------------
# Soledad WSGI application
#-----------------------------------------------------------------------------

class SoledadApp(http_app.HTTPApp):
    """
    Soledad WSGI application
    """

    SHARED_DB_NAME = 'shared'
    """
    The name of the shared database that holds user's encrypted secrets.
    """

    USER_DB_PREFIX = 'user-'
    """
    The string prefix of users' databases.
    """

    def __call__(self, environ, start_response):
        """
        Handle a WSGI call to the Soledad application.

        @param environ: Dictionary containing CGI variables.
        @type environ: dict
        @param start_response: Callable of the form start_response(status,
            response_headers, exc_info=None).
        @type start_response: callable

        @return: HTTP application results.
        @rtype: list
        """
        # ensure the shared database exists
        self.state.ensure_database(self.SHARED_DB_NAME)
        return http_app.HTTPApp.__call__(self, environ, start_response)


#-----------------------------------------------------------------------------
# Auxiliary functions
#-----------------------------------------------------------------------------

def load_configuration(file_path):
    """
    Load server configuration from file.

    @param file_path: The path to the configuration file.
    @type file_path: str

    @return: A dictionary with the configuration.
    @rtype: dict
    """
    conf = {
        'couch_url': 'http://localhost:5984',
    }
    config = configparser.ConfigParser()
    config.read(file_path)
    if 'soledad-server' in config:
        for key in conf:
            if key in config['soledad-server']:
                conf[key] = config['soledad-server'][key]
    # TODO: implement basic parsing/sanitization of options comming from
    # config file.
    return conf


#-----------------------------------------------------------------------------
# Run as Twisted WSGI Resource
#-----------------------------------------------------------------------------

conf = load_configuration('/etc/leap/soledad-server.conf')
state = CouchServerState(conf['couch_url'])

# WSGI application that may be used by `twistd -web`
application = SoledadTokenAuthMiddleware(SoledadApp(state))

resource = WSGIResource(reactor, reactor.getThreadPool(), application)

from ._version import get_versions
__version__ = get_versions()['version']
del get_versions
