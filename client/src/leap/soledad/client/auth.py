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
Methods for token-based authentication.

These methods have to be included in all classes that extend HTTPClient so
they can do token-based auth requests to the Soledad server.
"""
import base64

from u1db import errors


class TokenBasedAuth(object):
    """
    Encapsulate token-auth methods for classes that inherit from
    u1db.remote.http_client.HTTPClient.
    """

    def set_token_credentials(self, uuid, token):
        """
        Store given credentials so we can sign the request later.

        :param uuid: The user's uuid.
        :type uuid: str
        :param token: The authentication token.
        :type token: str
        """
        self._creds = {'token': (uuid, token)}

    def _sign_request(self, method, url_query, params):
        """
        Return an authorization header to be included in the HTTP request, in
        the form:

            [('Authorization', 'Token <(base64 encoded) uuid:token>')]

        :param method: The HTTP method.
        :type method: str
        :param url_query: The URL query string.
        :type url_query: str
        :param params: A list with encoded query parameters.
        :type param: list

        :return: The Authorization header.
        :rtype: list of tuple
        """
        if 'token' in self._creds:
            uuid, token = self._creds['token']
            auth = '%s:%s' % (uuid, token)
            b64_token = base64.b64encode(auth)
            return [('Authorization', 'Token %s' % b64_token)]
        else:
            raise errors.UnknownAuthMethod(
                'Wrong credentials: %s' % self._creds)
