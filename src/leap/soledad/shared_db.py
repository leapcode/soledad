# -*- coding: utf-8 -*-
"""
Created on Tue Mar  5 18:46:38 2013

@author: drebs
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
        """
        Open a Soledad shared database.
        """
        db = SoledadSharedDatabase(url, token=token)
        db.open(create)
        return db

    @staticmethod
    def delete_database(url):
        """
        Dummy method that prevents from deleting shared database.
        """
        raise Unauthorized("Can't delete shared database.")

    def __init__(self, url, document_factory=None, creds=None, token=None):
        """
        Initialize database with auth token and encryption powers.
        """
        self._token = token
        super(SoledadSharedDatabase, self).__init__(url, document_factory,
                                                    creds)

    def _request(self, method, url_parts, params=None, body=None,
                 content_type=None, auth=True):
        """
        Perform token-based http request.
        """
        # add the auth-token as a request parameter
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
        Perform token-based http request.
        """
        # allow for token-authenticated requests.
        res, headers = self._request(method, url_parts,
                                     params=params, body=body,
                                     content_type=content_type, auth=auth)
        return json.loads(res), headers

    def get_doc_unauth(self, doc_id):
        """
        Modified method to allow for unauth request.
        """
        db = http_database.HTTPDatabase(self._url.geturl(),
                                        document_factory=self._factory)
        return db.get_doc(doc_id)
