# -*- coding: utf-8 -*-
# lock_resource.py
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
LockResource: a lock based on a document in the shared database.
"""


import hashlib
import time
import os
import tempfile
import errno


from u1db.remote import http_app
from twisted.python.lockfile import FilesystemLock


from leap.soledad.common import (
    SHARED_DB_NAME,
    SHARED_DB_LOCK_DOC_ID_PREFIX,
)
from leap.soledad.common.errors import (
    InvalidTokenError,
    NotLockedError,
    AlreadyLockedError,
    LockTimedOutError,
    CouldNotObtainLockError,
)


class LockResource(object):
    """
    Handle requests for locking documents.

    This class uses Twisted's Filesystem lock to manage a lock in the shared
    database.
    """

    url_pattern = '/%s/lock/{uuid}' % SHARED_DB_NAME
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
        self._shared_db = state.open_database(SHARED_DB_NAME)
        self._lock_doc_id = '%s%s' % (SHARED_DB_LOCK_DOC_ID_PREFIX, uuid)
        self._lock = FilesystemLock(
            os.path.join(
                tempfile.gettempdir(),
                hashlib.sha512(self._lock_doc_id).hexdigest()))
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
            self._responder.send_response_json(
                LockTimedOutError.status,  # error: request timeout
                error=LockTimedOutError.wire_description)
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
            # respond success: should use 204 but u1db does not support it.
            self._responder.send_response_json(200)

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
            except OSError as e:
                tries -= 1
                if tries == 0:
                    raise CouldNotObtainLockError(e.message)
                time.sleep(self.FILESYSTEM_LOCK_SLEEP_SECONDS)
        return False

    def _try_release_filesystem_lock(self):
        """
        Release the filesystem lock.
        """
        try:
            self._lock.unlock()
            return True
        except OSError as e:
            if e.errno == errno.ENOENT:
                return True
            return False
