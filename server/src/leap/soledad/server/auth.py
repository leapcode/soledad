# -*- coding: utf-8 -*-
# auth.py
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
Authentication facilities for Soledad Server.
"""


import httplib
import json

from u1db import DBNAME_CONSTRAINTS, errors as u1db_errors
from abc import ABCMeta, abstractmethod
from routes.mapper import Mapper
from twisted.python import log

from leap.soledad.common import SHARED_DB_NAME
from leap.soledad.common import USER_DB_PREFIX


class URLToAuthorization(object):
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
        @param user_db_prefix: The string prefix of users' databases.
        @type user_db_prefix: str
        """
        self._map = Mapper(controller_scan=None)
        self._user_db_name = "%s%s" % (USER_DB_PREFIX, uuid)
        self._uuid = uuid
        self._register_auth_info()

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

    def _register_auth_info(self):
        """
        Register the authorization info in the mapper using C{SHARED_DB_NAME}
        as the user's database name.

        This method sets up the following authorization rules:

            URL path                      | Authorized actions
            --------------------------------------------------
            /                             | GET
            /shared-db                    | GET
            /shared-db/docs               | -
            /shared-db/doc/{any_id}       | GET, PUT, DELETE
            /shared-db/sync-from/{source} | -
            /shared-db/lock/{uuid}        | PUT, DELETE
            /user-db                      | GET, PUT, DELETE
            /user-db/docs                 | -
            /user-db/doc/{id}             | -
            /user-db/sync-from/{source}   | GET, PUT, POST
        """
        # auth info for global resource
        self._register('/', [self.HTTP_METHOD_GET])
        # auth info for shared-db database resource
        self._register(
            '/%s' % SHARED_DB_NAME,
            [self.HTTP_METHOD_GET])
        # auth info for shared-db doc resource
        self._register(
            '/%s/doc/{id:.*}' % SHARED_DB_NAME,
            [self.HTTP_METHOD_GET, self.HTTP_METHOD_PUT,
             self.HTTP_METHOD_DELETE])
        # auth info for shared-db lock resource
        self._register(
            '/%s/lock/%s' % (SHARED_DB_NAME, self._uuid),
            [self.HTTP_METHOD_PUT, self.HTTP_METHOD_DELETE])
        # auth info for user-db database resource
        self._register(
            '/%s' % self._user_db_name,
            [self.HTTP_METHOD_GET, self.HTTP_METHOD_PUT,
             self.HTTP_METHOD_DELETE])
        # auth info for user-db sync resource
        self._register(
            '/%s/sync-from/{source_replica_uid}' % self._user_db_name,
            [self.HTTP_METHOD_GET, self.HTTP_METHOD_PUT,
             self.HTTP_METHOD_POST])
        # generate the regular expressions
        self._map.create_regs()


class SoledadAuthMiddleware(object):
    """
    Soledad Authentication WSGI middleware.

    This class must be extended to implement specific authentication methods
    (see SoledadTokenAuthMiddleware below).

    It expects an HTTP_AUTHORIZATION header containing the concatenation of
    the following strings:

        1. The authentication scheme. It will be verified by the
           _verify_authentication_scheme() method.

        2. A space character.

        3. The base64 encoded string of the concatenation of the user uuid with
           the authentication data, separated by a collon, like this:

               base64("<uuid>:<auth_data>")

    After authentication check, the class performs an authorization check to
    verify whether the user is authorized to perform the requested action.

    On client-side, 2 methods must be implemented so the soledad client knows
    how to send authentication headers to server:

        * set_<method>_credentials: store authentication credentials in the
          class.

        * _sign_request: format and include custom authentication data in
          the HTTP_AUTHORIZATION header.

    See leap.soledad.auth and u1db.remote.http_client.HTTPClient to understand
    how to do it.
    """

    __metaclass__ = ABCMeta

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

    def _unauthorized_error(self, start_response, message):
        """
        Send a unauth error.

        @param message: The error message.
        @type message: str
        @param start_response: Callable of the form start_response(status,
            response_headers, exc_info=None).
        @type start_response: callable

        @return: List with JSON serialized error message.
        @rtype list
        """
        return self._error(
            start_response,
            401,
            "unauthorized",
            message)

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
        # check for authentication header
        auth = environ.get(self.HTTP_AUTH_KEY)
        if not auth:
            return self._unauthorized_error(
                start_response, "Missing authentication header.")

        # get authentication data
        scheme, encoded = auth.split(None, 1)
        uuid, auth_data = encoded.decode('base64').split(':', 1)
        if not self._verify_authentication_scheme(scheme):
            return self._unauthorized_error(
                start_response, "Wrong authentication scheme")

        # verify if user is athenticated
        try:
            if not self._verify_authentication_data(uuid, auth_data):
                return self._unauthorized_error(
                    start_response,
                    self._get_auth_error_string())
        except u1db_errors.Unauthorized as e:
            return self._error(
                start_response,
                401,
                e.wire_description)

        # verify if user is authorized to perform action
        if not self._verify_authorization(environ, uuid):
            return self._unauthorized_error(
                start_response,
                "Unauthorized action.")

        # move on to the real Soledad app
        del environ[self.HTTP_AUTH_KEY]
        return self._app(environ, start_response)

    @abstractmethod
    def _verify_authentication_scheme(self, scheme):
        """
        Verify if authentication scheme is valid.

        @param scheme: Auth scheme extracted from the HTTP_AUTHORIZATION
            header.
        @type scheme: str

        @return: Whether the authentitcation scheme is valid.
        """
        return None

    @abstractmethod
    def _verify_authentication_data(self, uuid, auth_data):
        """
        Verify valid authenticatiion for this request.

        @param uuid: The user's uuid.
        @type uuid: str
        @param auth_data: Authentication data.
        @type auth_data: str

        @return: Whether the token is valid for authenticating the request.
        @rtype: bool

        @raise Unauthorized: Raised when C{auth_data} is not enough to
                             authenticate C{uuid}.
        """
        return None

    def _verify_authorization(self, environ, uuid):
        """
        Verify if the user is authorized to perform the requested action over
        the requested database.

        @param environ: Dictionary containing CGI variables.
        @type environ: dict
        @param uuid: The user's uuid.
        @type uuid: str

        @return: Whether the user is authorize to perform the requested action
            over the requested db.
        @rtype: bool
        """
        return URLToAuthorization(uuid).is_authorized(environ)

    @abstractmethod
    def _get_auth_error_string(self):
        """
        Return an error string specific for each kind of authentication method.

        @return: The error string.
        """
        return None


class SoledadTokenAuthMiddleware(SoledadAuthMiddleware):
    """
    Token based authentication.
    """

    TOKEN_AUTH_ERROR_STRING = "Incorrect address or token."

    def __init__(self, app):
        self._state = app.state
        super(SoledadTokenAuthMiddleware, self).__init__(app)

    def _verify_authentication_scheme(self, scheme):
        """
        Verify if authentication scheme is valid.

        @param scheme: Auth scheme extracted from the HTTP_AUTHORIZATION
            header.
        @type scheme: str

        @return: Whether the authentitcation scheme is valid.
        """
        if scheme.lower() != 'token':
            return False
        return True

    def _verify_authentication_data(self, uuid, auth_data):
        """
        Extract token from C{auth_data} and proceed with verification of
        C{uuid} authentication.

        @param uuid: The user UID.
        @type uuid: str
        @param auth_data: Authentication data (i.e. the token).
        @type auth_data: str

        @return: Whether the token is valid for authenticating the request.
        @rtype: bool

        @raise Unauthorized: Raised when C{auth_data} is not enough to
                             authenticate C{uuid}.
        """
        token = auth_data  # we expect a cleartext token at this point
        try:
            return self._state.verify_token(uuid, token)
        except Exception as e:
            log.err(e)
            return False

    def _get_auth_error_string(self):
        """
        Get the error string for token auth.

        @return: The error string.
        """
        return self.TOKEN_AUTH_ERROR_STRING
