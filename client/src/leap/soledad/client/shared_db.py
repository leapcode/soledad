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

import simplejson as json


from u1db.remote import http_database


from leap.soledad.common import SHARED_DB_LOCK_DOC_ID_PREFIX
from leap.soledad.client.auth import TokenBasedAuth


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


class SoledadSharedDatabase(http_database.HTTPDatabase, TokenBasedAuth):
    """
    This is a shared recovery database that enables users to store their
    encryption secrets in the server and retrieve them afterwards.
    """
    # TODO: prevent client from messing with the shared DB.
    # TODO: define and document API.

    #
    # Token auth methods.
    #

    def set_token_credentials(self, uuid, token):
        """
        Store given credentials so we can sign the request later.

        :param uuid: The user's uuid.
        :type uuid: str
        :param token: The authentication token.
        :type token: str
        """
        TokenBasedAuth.set_token_credentials(self, uuid, token)

    def _sign_request(self, method, url_query, params):
        """
        Return an authorization header to be included in the HTTP request.

        :param method: The HTTP method.
        :type method: str
        :param url_query: The URL query string.
        :type url_query: str
        :param params: A list with encoded query parameters.
        :type param: list

        :return: The Authorization header.
        :rtype: list of tuple
        """
        return TokenBasedAuth._sign_request(self, method, url_query, params)

    #
    # Modified HTTPDatabase methods.
    #

    @staticmethod
    def open_database(url, uuid, create, creds=None):
        # TODO: users should not be able to create the shared database, so we
        # have to remove this from here in the future.
        """
        Open a Soledad shared database.

        :param url: URL of the remote database.
        :type url: str
        :param uuid: The user's unique id.
        :type uuid: str
        :param create: Should the database be created if it does not already
                       exist?
        :type create: bool
        :param token: An authentication token for accessing the shared db.
        :type token: str

        :return: The shared database in the given url.
        :rtype: SoledadSharedDatabase
        """
        db = SoledadSharedDatabase(url, uuid, creds=creds)
        db.open(create)
        return db

    @staticmethod
    def delete_database(url):
        """
        Dummy method that prevents from deleting shared database.

        :raise: This will always raise an Unauthorized exception.

        :param url: The database URL.
        :type url: str
        """
        raise Unauthorized("Can't delete shared database.")

    def __init__(self, url, uuid, document_factory=None, creds=None):
        """
        Initialize database with auth token and encryption powers.

        :param url: URL of the remote database.
        :type url: str
        :param uuid: The user's unique id.
        :type uuid: str
        :param document_factory: A factory for U1BD documents.
        :type document_factory: u1db.Document
        :param creds: A tuple containing the authentication method and
            credentials.
        :type creds: tuple
        """
        http_database.HTTPDatabase.__init__(self, url, document_factory,
                                            creds)
        self._uuid = uuid

    def lock(self):
        """
        Obtain a lock on document with id C{doc_id}.

        :return: A tuple containing the token to unlock and the timeout until
                 lock expiration.
        :rtype: (str, float)

        :raise HTTPError: Raised if any HTTP error occurs.
        """
        res, headers = self._request_json('PUT', ['lock', self._uuid],
                                          body={})
        return res['token'], res['timeout']

    def unlock(self, token):
        """
        Release the lock on shared database.

        :param token: The token returned by a previous call to lock().
        :type token: str

        :raise HTTPError:
        """
        res, headers = self._request_json('DELETE', ['lock', self._uuid],
                                          params={'token': token})
