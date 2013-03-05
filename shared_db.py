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
    This is a shared HTTP database that holds users' encrypted keys.
    """
    # TODO: prevent client from messing with the shared DB.
    # TODO: define and document API.

    @staticmethod
    def open_database(url, create, token=None, soledad=None):
        """
        Open a Soledad shared database.
        """
        db = SoledadSharedDatabase(url, token=token, soledad=soledad)
        db.open(create)
        return db

    @staticmethod
    def delete_database(url):
        """
        Dummy method that prevents from deleting shared database.
        """
        raise Unauthorized("Can't delete shared database.")

    def __init__(self, url, document_factory=None, creds=None, token=None,
                 soledad=None):
        self._token = token
        self._soledad = soledad
        super(SoledadSharedDatabase, self).__init__(url, document_factory,
                                                    creds)

    def _request(self, method, url_parts, params=None, body=None,
                 content_type=None, auth=True):
        """
        Perform token-based http request.
        """
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
        res, headers = self._request(method, url_parts,
                                     params=params, body=body,
                                     content_type=content_type, auth=auth)
        return json.loads(res), headers

    def get_doc_unauth(self, doc_id):
        """
        Modified method to allow for unauth request.
        """
        try:
            res, headers = self._request(
                'GET', ['doc', doc_id], {"include_deleted": False},
                auth=False)
        except errors.DocumentDoesNotExist:
            return None
        except errors.HTTPError, e:
            if (e.status == http_database.DOCUMENT_DELETED_STATUS and
                    'x-u1db-rev' in e.headers):
                res = None
                headers = e.headers
            else:
                raise
        doc_rev = headers['x-u1db-rev']
        has_conflicts = json.loads(headers['x-u1db-has-conflicts'])
        doc = self._factory(doc_id, doc_rev, res)
        doc.has_conflicts = has_conflicts
        return doc
