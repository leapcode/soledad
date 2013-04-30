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
    twistd -n web --wsgi=leap.soledad.server.application
"""

import configparser
import httplib
try:
    import simplejson as json
except ImportError:
    import json  # noqa


from urlparse import parse_qs
from wsgiref.util import shift_path_info
from twisted.web.wsgi import WSGIResource
from twisted.internet import reactor
from u1db.remote import http_app
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

    def __init__(self, app, prefix, public_dbs=None):
        """
        Initialize the Soledad Authentication Middleware.

        @param app: The application to run on successfull authentication.
        @type app: u1db.remote.http_app.HTTPApp
        @param prefix: Auth app path prefix.
        @type prefix: str
        @param public_dbs: List of databases that should bypass
            authentication.
        @type public_dbs: list
        """
        self.app = app
        self.prefix = prefix
        self.public_dbs = public_dbs

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
                       [('content-type', 'application/json')])
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
        if self.prefix and not environ['PATH_INFO'].startswith(self.prefix):
            return self._error(start_response, 400, "bad request")
        auth = environ.get('HTTP_AUTHORIZATION')
        if not auth:
            return self._error(start_response, 401, "unauthorized",
                               "Missing Token Authentication.")
        scheme, encoded = auth.split(None, 1)
        if scheme.lower() != 'token':
            return self._error(
                start_response, 401, "unauthorized",
                "Missing Token Authentication")
        uuid, token = encoded.decode('base64').split(':', 1)
        try:
            self.verify_token(environ, uuid, token)
        except Unauthorized:
            return self._error(
                start_response, 401, "unauthorized",
                "Incorrect uuid or token.")
        del environ['HTTP_AUTHORIZATION']
        shift_path_info(environ)
        return self.app(environ, start_response)

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
        # TODO: implement token verification
        return True
        #raise NotImplementedError(self.verify_token)

    def need_auth(self, environ):
        """
        Check if action can be performed on database without authentication.

        For now, just allow access to /shared/*.

        @param environ: Dictionary containing CGI variables.
        @type environ: dict

        @return: Whether the requests needs authentication.
        @rtype: bool
        """
        # TODO: design unauth verification.
        # TODO: include public_dbs here or remove it from code.
        return not environ.get('PATH_INFO').startswith('/shared/')


#-----------------------------------------------------------------------------
# Soledad WSGI application
#-----------------------------------------------------------------------------

class SoledadApp(http_app.HTTPApp):
    """
    Soledad WSGI application
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
        # TODO: this is a hack for tests to pass, we should remove it asap.
        #if environ['CONTENT_LENGTH'] == '':
        #    environ['CONTENT_LENGTH'] = 1
        #import ipdb; ipdb.set_trace()
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
        'working_dir': '/tmp',
        'public_dbs': 'keys',
        'prefix': '/soledad/',
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

# TODO: create command-line option for choosing config file.
conf = load_configuration('/etc/leap/soledad-server.ini')
state = CouchServerState(conf['couch_url'])
# TODO: change working dir to something meaningful (maybe eliminate it)
state.set_workingdir(conf['working_dir'])

application = SoledadAuthMiddleware(
    SoledadApp(state),
    conf['prefix'],
    conf['public_dbs'].split(','))

resource = WSGIResource(reactor, reactor.getThreadPool(), application)
