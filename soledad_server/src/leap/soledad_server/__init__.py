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
import httplib
import simplejson as json


from hashlib import sha256
from routes.mapper import Mapper
from u1db import DBNAME_CONSTRAINTS
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

from leap.soledad import SECRETS_DOC_ID_HASH_PREFIX
from leap.soledad_server.couch import CouchServerState


#-----------------------------------------------------------------------------
# Authentication
#-----------------------------------------------------------------------------

class Unauthorized(Exception):
    """
    User authentication failed.
    """


class URLToAuth(object):
    """
    Verify if actions can be performed by a user.
    """

    HTTP_METHOD_GET = 'GET'
    HTTP_METHOD_PUT = 'PUT'
    HTTP_METHOD_DELETE = 'DELETE'
    HTTP_METHOD_POST = 'POST'

    def __init__(self, uuid):
        """
        Initialize the mapper.

        The C{uuid} is used to create the rules that will either allow or
        disallow the user to perform specific actions.

        @param uuid: The user uuid.
        @type uuid: str
        """
        self._map = Mapper(controller_scan=None)
        self._register_auth_info(self._uuid_dbname(uuid))

    def is_authorized(self, environ):
        """
        Return whether an HTTP request that produced the CGI C{environ}
        corresponds to an authorized action.

        @param environ: Dictionary containing CGI variables.
        @type environ: dict

        @return: Whether the action is authorized or not.
        @rtype: bool
        """
        return self._map.match(environ=environ) is not None

    def _register(self, pattern, http_methods):
        """
        Register a C{pattern} in the mapper as valid for C{http_methods}.

        @param pattern: The URL pattern that corresponds to the user action.
        @type pattern: str
        @param http_methods: A list of authorized HTTP methods.
        @type http_methods: list of str
        """
        self._map.connect(
            None, pattern, http_methods=http_methods,
            conditions=dict(method=http_methods),
            requirements={'dbname': DBNAME_CONSTRAINTS})

    def _uuid_dbname(self, uuid):
        """
        Return the database name corresponding to C{uuid}.

        @param uuid: The user uid.
        @type uuid: str

        @return: The database name corresponding to C{uuid}.
        @rtype: str
        """
        return '%s%s' % (SoledadApp.USER_DB_PREFIX, uuid)

    def _register_auth_info(self, dbname):
        """
        Register the authorization info in the mapper using C{dbname} as the
        user's database name.

        This method sets up the following authorization rules:

            URL path                      | Authorized actions
            --------------------------------------------------
            /                             | GET
            /shared-db                    | GET
            /shared-db/docs               | -
            /shared-db/doc/{id}           | GET, PUT, DELETE
            /shared-db/sync-from/{source} | -
            /user-db                      | GET, PUT, DELETE
            /user-db/docs                 | -
            /user-db/doc/{id}             | -
            /user-db/sync-from/{source}   | GET, PUT, POST

        @param dbname: The name of the user's database.
        @type dbname: str
        """
        # auth info for global resource
        self._register('/', [self.HTTP_METHOD_GET])
        # auth info for shared-db database resource
        self._register(
            '/%s' % SoledadApp.SHARED_DB_NAME,
            [self.HTTP_METHOD_GET])
        # auth info for shared-db doc resource
        self._register(
            '/%s/doc/{id:.*}' % SoledadApp.SHARED_DB_NAME,
            [self.HTTP_METHOD_GET, self.HTTP_METHOD_PUT,
             self.HTTP_METHOD_DELETE])
        # auth info for user-db database resource
        self._register(
            '/%s' % dbname,
            [self.HTTP_METHOD_GET, self.HTTP_METHOD_PUT,
             self.HTTP_METHOD_DELETE])
        # auth info for user-db sync resource
        self._register(
            '/%s/sync-from/{source_replica_uid}' % dbname,
            [self.HTTP_METHOD_GET, self.HTTP_METHOD_PUT,
             self.HTTP_METHOD_POST])
        # generate the regular expressions
        self._map.create_regs()


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

        if not self.verify_action(uuid, environ):
            return unauth_err("Unauthorized action.")

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

    def verify_action(self, uuid, environ):
        """
        Verify if the user is authorized to perform the requested action over
        the requested database.

        @param uuid: The user's uuid.
        @type uuid: str
        @param environ: Dictionary containing CGI variables.
        @type environ: dict

        @return: Whether the user is authorize to perform the requested action
            over the requested db.
        @rtype: bool
        """
        return URLToAuth(uuid).is_authorized(environ)


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

    USER_DB_PREFIX = 'uuid-'
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
application = SoledadAuthMiddleware(SoledadApp(state))

resource = WSGIResource(reactor, reactor.getThreadPool(), application)
