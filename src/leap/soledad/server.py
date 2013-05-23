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
    twistd -n web --wsgi=leap.soledad.server.application --port=2424
"""

import configparser
import httplib
try:
    import simplejson as json
except ImportError:
    import json  # noqa

from u1db.remote import http_app

# Keep OpenSSL's tsafe before importing Twisted submodules so we can put
# it back if Twisted==12.0.0 messes with it.
from OpenSSL import tsafe
old_tsafe = tsafe

from twisted.web.wsgi import WSGIResource
from twisted.internet import reactor
from twisted.python import log

from twisted import version
if version.base() == "12.0.0":
    # Put OpenSSL's tsafe back into place. This can probably be removed if we
    # come to use Twisted>=12.3.0.
    import sys
    sys.modules['OpenSSL.tsafe'] = old_tsafe

from couchdb.client import Server

from leap.soledad.backends.couch import CouchServerState


#-----------------------------------------------------------------------------
# Authentication
#-----------------------------------------------------------------------------

class Unauthorized(Exception):
    """
    User authentication failed.
    """


class SoledadAuthMiddleware(object):
    """
    Soledad Authentication WSGI middleware.

    In general, databases are accessed using a token provided by the LEAP API.
    Some special databases can be read without authentication.
    """

    TOKENS_DB = "tokens"
    TOKENS_TYPE_KEY = "type"
    TOKENS_TYPE_DEF = "Token"
    TOKENS_USER_ID_KEY = "user_id"

    HTTP_AUTH_KEY = "HTTP_AUTHORIZATION"
    PATH_INFO_KEY = "PATH_INFO"

    CONTENT_TYPE_JSON = ('content-type', 'application/json')

    def __init__(self, app):
        """
        Initialize the Soledad Authentication Middleware.

        @param app: The application to run on successfull authentication.
        @type app: u1db.remote.http_app.HTTPApp
        @param prefix: Auth app path prefix.
        @type prefix: str
        """
        self._app = app

    def _error(self, start_response, status, description, message=None):
        """
        Send a JSON serialized error to WSGI client.

        @param start_response: Callable of the form start_response(status,
            response_headers, exc_info=None).
        @type start_response: callable
        @param status: Status string of the form "999 Message here"
        @type status: str
        @param response_headers: A list of (header_name, header_value) tuples
            describing the HTTP response header.
        @type response_headers: list
        @param description: The error description.
        @type description: str
        @param message: The error message.
        @type message: str

        @return: List with JSON serialized error message.
        @rtype list
        """
        start_response("%d %s" % (status, httplib.responses[status]),
                       [self.CONTENT_TYPE_JSON])
        err = {"error": description}
        if message:
            err['message'] = message
        return [json.dumps(err)]

    def __call__(self, environ, start_response):
        """
        Handle a WSGI call to the authentication application.

        @param environ: Dictionary containing CGI variables.
        @type environ: dict
        @param start_response: Callable of the form start_response(status,
            response_headers, exc_info=None).
        @type start_response: callable

        @return: Target application results if authentication succeeds, an
        error message otherwise.
        @rtype: list
        """
        unauth_err = lambda msg: self._error(start_response,
                                             401,
                                             "unauthorized",
                                             msg)

        auth = environ.get(self.HTTP_AUTH_KEY)
        if not auth:
            return unauth_err("Missing Token Authentication.")

        scheme, encoded = auth.split(None, 1)
        if scheme.lower() != 'token':
            return unauth_err("Missing Token Authentication")

        uuid, token = encoded.decode('base64').split(':', 1)
        if not self.verify_token(environ, uuid, token):
            return unauth_err("Incorrect address or token.")

        del environ[self.HTTP_AUTH_KEY]

        return self._app(environ, start_response)

    def verify_token(self, environ, uuid, token):
        """
        Verify if token is valid for authenticating this request.

        @param environ: Dictionary containing CGI variables.
        @type environ: dict
        @param uuid: The user's uuid.
        @type uuid: str
        @param token: The authentication token.
        @type token: str

        @return: Whether the token is valid for authenticating the request.
        @rtype: bool
        """

        server = Server(url=self._app.state.couch_url)
        try:
            dbname = self.TOKENS_DB
            db = server[dbname]
            token = db.get(token)
            if token is None:
                return False
            return token[self.TOKENS_TYPE_KEY] == self.TOKENS_TYPE_DEF and \
                token[self.TOKENS_USER_ID_KEY] == uuid
        except Exception as e:
            log.err(e)
            return False
        return True


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
application = SoledadAuthMiddleware(SoledadApp(state))

resource = WSGIResource(reactor, reactor.getThreadPool(), application)
