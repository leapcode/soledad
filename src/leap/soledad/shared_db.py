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

from u1db.remote import http_database, http_client


from leap.soledad.auth import (
    set_token_credentials,
    _sign_request,
)

SOLEDAD_CERT = None

#-----------------------------------------------------------------------------
# Monkey patching u1db to be able to provide a custom SSL cert
#-----------------------------------------------------------------------------

import httplib
import socket
import ssl

class VerifiedHTTPSConnection(httplib.HTTPSConnection):
    """HTTPSConnection verifying server side certificates."""
    # derived from httplib.py

    def connect(self):
        "Connect to a host on a given (SSL) port."
        sock = socket.create_connection((self.host, self.port),
                                        self.timeout, self.source_address)
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
        self.sock = ssl.wrap_socket(sock, self.key_file, SOLEDAD_CERT,
                                    ssl_version=ssl.PROTOCOL_SSLv3,
                                    cert_reqs=ssl.CERT_REQUIRED,
                                    ca_certs=SOLEDAD_CERT)

http_client._VerifiedHTTPSConnection = VerifiedHTTPSConnection

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
    This is a shared recovery database that enables users to store their
    encryption secrets in the server and retrieve them afterwards.
    """
    # TODO: prevent client from messing with the shared DB.
    # TODO: define and document API.

    #
    # Token auth methods.
    #

    set_token_credentials = set_token_credentials

    _sign_request = _sign_request

    #
    # Modified HTTPDatabase methods.
    #

    @staticmethod
    def open_database(url, create, creds=None):
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
        db = SoledadSharedDatabase(url, creds=creds)
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

    def __init__(self, url, document_factory=None, creds=None):
        """
        Initialize database with auth token and encryption powers.

        @param url: URL of the remote database.
        @type url: str
        @param document_factory: A factory for U1BD documents.
        @type document_factory: u1db.Document
        @param creds: A tuple containing the authentication method and
            credentials.
        @type creds: tuple
        """
        http_database.HTTPDatabase.__init__(self, url, document_factory,
                                            creds)
