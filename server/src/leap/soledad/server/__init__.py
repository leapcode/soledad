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

General information
===================

This is written as a Twisted application and intended to be run using the
twistd command. To start the soledad server, run:

    twistd -n web --wsgi=leap.soledad.server.application --port=X

An initscript is included and will be installed system wide to make it
feasible to start and stop the Soledad server service using a standard
interface.

Server database organization
============================

Soledad Server works with one database per user and one shared database in
which user's encrypted secrets might be stored.

User database
-------------

Users' databases in the server are named 'user-<uuid>' and Soledad Client
may perform synchronization between its local replicas and the user's
database in the server. Authorization for creating, updating, deleting and
retrieving information about the user database as well as performing
synchronization is handled by the `leap.soledad.server.auth` module.

Shared database
---------------

Each user may store password-encrypted recovery data in the shared database,
as well as obtain a lock on the shared database in order to prevent creation
of multiple secrets in parallel.

Recovery documents are stored in the database without any information that
may identify the user. In order to achieve this, the doc_id of recovery
documents are obtained as a hash of the user's uid and the user's password.
User's must have a valid token to interact with recovery documents, but the
server does not perform further authentication because it has no way to know
which recovery document belongs to each user.

This has some implications:

  * The security of the recovery document doc_id, and thus of access to the
    recovery document (encrypted) content, as well as tampering with the
    stored data, all rely on the difficulty of obtaining the user's password
    (supposing the user's uid is somewhat public) and the security of the hash
    function used to calculate the doc_id.

  * The security of the content of a recovery document relies on the
    difficulty of obtaining the user's password.

  * If the user looses his/her password, he/she will not be able to obtain the
    recovery document.

  * Because of the above, it is recommended that recovery documents expire
    (not implemented yet) to prevent excess storage.

Lock documents, on the other hand, may be more thoroughly protected by the
server. Their doc_id's are calculated from the SHARED_DB_LOCK_DOC_ID_PREFIX
and the user's uid.

The authorization for creating, updating, deleting and retrieving recovery
and lock documents on the shared database is handled by
`leap.soledad.server.auth` module.
"""

import configparser
import time
import hashlib
import os

from u1db.remote import http_app

# Keep OpenSSL's tsafe before importing Twisted submodules so we can put
# it back if Twisted==12.0.0 messes with it.
from OpenSSL import tsafe
old_tsafe = tsafe

from twisted.web.wsgi import WSGIResource
from twisted.internet import reactor
from twisted.internet.error import TimeoutError
from twisted.python.lockfile import FilesystemLock
from twisted import version
if version.base() == "12.0.0":
    # Put OpenSSL's tsafe back into place. This can probably be removed if we
    # come to use Twisted>=12.3.0.
    import sys
    sys.modules['OpenSSL.tsafe'] = old_tsafe

from leap.soledad.server.auth import SoledadTokenAuthMiddleware
from leap.soledad.common import (
    SHARED_DB_NAME,
    SHARED_DB_LOCK_DOC_ID_PREFIX,
)
from leap.soledad.common.couch import CouchServerState
from leap.soledad.common.errors import (
    InvalidTokenError,
    NotLockedError,
    AlreadyLockedError,
)


#-----------------------------------------------------------------------------
# Soledad WSGI application
#-----------------------------------------------------------------------------

class SoledadApp(http_app.HTTPApp):
    """
    Soledad WSGI application
    """

    SHARED_DB_NAME = SHARED_DB_NAME
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


#
# LockResource: a lock based on a document in the shared database.
#

@http_app.url_to_resource.register
class LockResource(object):
    """
    Handle requests for locking documents.

    This class uses Twisted's Filesystem lock to manage a lock in the shared
    database.
    """

    url_pattern = '/%s/lock/{uuid}' % SoledadApp.SHARED_DB_NAME
    """
    """

    TIMEOUT = 300  # XXX is 5 minutes reasonable?
    """
    The timeout after which the lock expires.
    """

    # used for lock doc storage
    TIMESTAMP_KEY = '_timestamp'
    LOCK_TOKEN_KEY = '_token'

    FILESYSTEM_LOCK_TRIES = 5
    FILESYSTEM_LOCK_SLEEP_SECONDS = 1


    def __init__(self, uuid, state, responder):
        """
        Initialize the lock resource. Parameters to this constructor are
        automatically passed by u1db.

        :param uuid: The user unique id.
        :type uuid: str
        :param state: The backend database state.
        :type state: u1db.remote.ServerState
        :param responder: The infrastructure to send responses to client.
        :type responder: u1db.remote.HTTPResponder
        """
        self._shared_db = state.open_database(SoledadApp.SHARED_DB_NAME)
        self._lock_doc_id = '%s%s' % (SHARED_DB_LOCK_DOC_ID_PREFIX, uuid)
        self._lock = FilesystemLock(
            hashlib.sha512(self._lock_doc_id).hexdigest())
        self._state = state
        self._responder = responder

    @http_app.http_method(content=str)
    def put(self, content=None):
        """
        Handle a PUT request to the lock document.

        A lock is a document in the shared db with doc_id equal to
        'lock-<uuid>' and the timestamp of its creation as content. This
        method obtains a threaded-lock and creates a lock document if it does
        not exist or if it has expired.

        It returns '201 Created' and a pair containing a token to unlock and
        the lock timeout, or '403 AlreadyLockedError' and the remaining amount
        of seconds the lock will still be valid.

        :param content: The content of the PUT request. It is only here
                        because PUT requests with empty content are considered
                        invalid requests by u1db.
        :type content: str
        """
        # obtain filesystem lock
        if not self._try_obtain_filesystem_lock():
            self._responder.send_response_json(408)  # error: request timeout
            return

        created_lock = False
        now = time.time()
        token = hashlib.sha256(os.urandom(10)).hexdigest()  # for releasing
        lock_doc = self._shared_db.get_doc(self._lock_doc_id)
        remaining = self._remaining(lock_doc, now)

        # if there's no lock, create one
        if lock_doc is None:
            lock_doc = self._shared_db.create_doc(
                {
                    self.TIMESTAMP_KEY: now,
                    self.LOCK_TOKEN_KEY: token,
                },
                doc_id=self._lock_doc_id)
            created_lock = True
        else:
            if remaining == 0:
                # lock expired, create new one
                lock_doc.content = {
                    self.TIMESTAMP_KEY: now,
                    self.LOCK_TOKEN_KEY: token,
                }
                self._shared_db.put_doc(lock_doc)
                created_lock = True

        self._try_release_filesystem_lock()

        # send response to client
        if created_lock is True:
            self._responder.send_response_json(
                201, timeout=self.TIMEOUT, token=token)  # success: created
        else:
            wire_descr = AlreadyLockedError.wire_description
            self._responder.send_response_json(
                AlreadyLockedError.status,  # error: forbidden
                error=AlreadyLockedError.wire_description, remaining=remaining)

    @http_app.http_method(token=str)
    def delete(self, token=None):
        """
        Delete the lock if the C{token} is valid.

        Delete the lock document in case C{token} is equal to the token stored
        in the lock document.

        :param token: The token returned when locking.
        :type token: str

        :raise NotLockedError: Raised in case the lock is not locked.
        :raise InvalidTokenError: Raised in case the token is invalid for
                                  unlocking.
        """
        lock_doc = self._shared_db.get_doc(self._lock_doc_id)
        if lock_doc is None or self._remaining(lock_doc, time.time()) == 0:
            self._responder.send_response_json(
                NotLockedError.status,  # error: not found
                error=NotLockedError.wire_description)
        elif token != lock_doc.content[self.LOCK_TOKEN_KEY]:
            self._responder.send_response_json(
                InvalidTokenError.status,  # error: unauthorized
                error=InvalidTokenError.wire_description)
        else:
            self._shared_db.delete_doc(lock_doc)
            self._responder.send_response_json(200)  # success: should use 204
                                                     # but u1db does not
                                                     # support it.

    def _remaining(self, lock_doc, now):
        """
        Return the number of seconds the lock contained in C{lock_doc} is
        still valid, when compared to C{now}.

        :param lock_doc: The document containing the lock.
        :type lock_doc: u1db.Document
        :param now: The time to which to compare the lock timestamp.
        :type now: float

        :return: The amount of seconds the lock is still valid.
        :rtype: float
        """
        if lock_doc is not None:
            lock_timestamp = lock_doc.content[self.TIMESTAMP_KEY]
            remaining = lock_timestamp + self.TIMEOUT - now
            return remaining if remaining > 0 else 0.0
        return 0.0

    def _try_obtain_filesystem_lock(self):
        """
        Try to obtain the file system lock.

        @return: Whether the lock was succesfully obtained.
        @rtype: bool
        """
        tries = self.FILESYSTEM_LOCK_TRIES
        while tries > 0:
            try:
                return self._lock.lock()
            except Exception as e:
                tries -= 1
                time.sleep(self.FILESYSTEM_LOCK_SLEEP_SECONDS)
        return False

    def _try_release_filesystem_lock(self):
        """
        Release the filesystem lock.
        """
        try:
            self._lock.unlock()
            return True
        except Exception:
            return False


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

def application(environ, start_response):
    conf = load_configuration('/etc/leap/soledad-server.conf')
    state = CouchServerState(
        conf['couch_url'],
        SoledadApp.SHARED_DB_NAME,
        SoledadTokenAuthMiddleware.TOKENS_DB)
    # WSGI application that may be used by `twistd -web`
    application = SoledadTokenAuthMiddleware(SoledadApp(state))
    resource = WSGIResource(reactor, reactor.getThreadPool(), application)
    return application(environ, start_response)


from ._version import get_versions
__version__ = get_versions()['version']
del get_versions
