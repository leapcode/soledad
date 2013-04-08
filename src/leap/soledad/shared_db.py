# -*- coding: utf-8 -*-
# shared_db.py
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
A shared database for storing/retrieving encrypted key material.
"""

try:
    import simplejson as json
except ImportError:
    import json  # noqa


from u1db import errors
from u1db.remote import http_database


#-----------------------------------------------------------------------------
# Soledad shared database
#-----------------------------------------------------------------------------

class NoTokenForAuth(Exception):
    """
    No token was found for token-based authentication.
    """


class Unauthorized(Exception):
    """
    User does not have authorization to perform task.
    """


class SoledadSharedDatabase(http_database.HTTPDatabase):
    """
    This is a shared remote database that holds users' encrypted keys.

    An authorization token is attached to every request other than
    get_doc_unauth, which has the purpose of retrieving encrypted content from
    the shared database without the need to associate user information with
    the request.
    """
    # TODO: prevent client from messing with the shared DB.
    # TODO: define and document API.

    @staticmethod
    def open_database(url, create, token=None):
        # TODO: users should not be able to create the shared database, so we
        # have to remove this from here in the future.
        """
        Open a Soledad shared database.

        @param url: URL of the remote database.
        @type url: str
        @param create: Should the database be created if it does not already
            exist?
        @type create: bool
        @param token: An authentication token for accessing the shared db.
        @type token: str

        @return: The shared database in the given url.
        @rtype: SoledadSharedDatabase
        """
        db = SoledadSharedDatabase(url, token=token)
        db.open(create)
        return db

    @staticmethod
    def delete_database(url):
        """
        Dummy method that prevents from deleting shared database.

        @raise: This will always raise an Unauthorized exception.

        @param url: The database URL.
        @type url: str
        """
        raise Unauthorized("Can't delete shared database.")

    def __init__(self, url, document_factory=None, creds=None, token=None):
        """
        Initialize database with auth token and encryption powers.

        @param url: URL of the remote database.
        @type url: str
        @param document_factory: A factory for U1BD documents.
        @type document_factory: u1db.Document
        @param creds: A tuple containing the authentication method and
            credentials.
        @type creds: tuple
        @param token: An authentication token for accessing the shared db.
        @type token: str
        """
        self._token = token
        super(SoledadSharedDatabase, self).__init__(url, document_factory,
                                                    creds)

    def _request(self, method, url_parts, params=None, body=None,
                 content_type=None, auth=True):
        """
        Perform token-based http request.

        @param method: The HTTP method for the request.
        @type method: str
        @param url_parts: A list with extra parts for the URL.
        @type url_parts: list
        @param params: Parameters to be added as query string.
        @type params: dict
        @param body: The body of the request (must be JSON serializable).
        @type body: object
        @param content_type: The content-type of the request.
        @type content_type: str
        @param auth: Should the request be authenticated?
        @type auth: bool

        @raise u1db.errors.Unavailable: If response status is 503.
        @raise u1db.errors.HTTPError: If response status is neither 200, 201
            or 503

        @return: The headers and body of the HTTP response.
        @rtype: tuple
        """
        # add `auth-token` as a request parameter
        if auth:
            if not self._token:
                raise NoTokenForAuth()
            if not params:
                params = {}
            params['auth_token'] = self._token
        return super(SoledadSharedDatabase, self)._request(
            method, url_parts,
            params,
            body,
            content_type)

    def _request_json(self, method, url_parts, params=None, body=None,
                      content_type=None, auth=True):
        """
        Perform token-based http request and deserialize the JSON results.

        @param method: The HTTP method for the request.
        @type method: str
        @param url_parts: A list with extra parts for the URL.
        @type url_parts: list
        @param params: Parameters to be added as query string.
        @type params: dict
        @param body: The body of the request (must be JSON serializable).
        @type body: object
        @param content_type: The content-type of the request.
        @type content_type: str
        @param auth: Should the request be authenticated?
        @type auth: bool

        @raise u1db.errors.Unavailable: If response status is 503.
        @raise u1db.errors.HTTPError: If response status is neither 200, 201
            or 503

        @return: The headers and body of the HTTP response.
        @rtype: tuple
        """
        # allow for token-authenticated requests.
        res, headers = self._request(method, url_parts,
                                     params=params, body=body,
                                     content_type=content_type, auth=auth)
        return json.loads(res), headers

    def get_doc_unauth(self, doc_id):
        """
        Modified method to allow for unauth request.

        This is the only (public) way to make an unauthenticaded request on
        the shared database.

        @param doc_id: The document id.
        @type doc_id: str

        @return: The requested document.
        @rtype: Document
        """
        db = http_database.HTTPDatabase(self._url.geturl(),
                                        document_factory=self._factory)
        return db.get_doc(doc_id)
