# -*- coding: utf-8 -*-
# errors.py
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
Soledad errors.
"""


from u1db import errors
from u1db.remote import http_errors


def register_exception(cls):
    """
    A small decorator that registers exceptions in u1db maps.
    """
    # update u1db "wire description to status" and "wire description to
    # exception" maps.
    http_errors.wire_description_to_status.update({
        cls.wire_description: cls.status})
    errors.wire_description_to_exc.update({
        cls.wire_description: cls})
    # do not modify the exception
    return cls


class SoledadError(errors.U1DBError):

    """
    Base Soledad HTTP errors.
    """
    pass


#
# Authorization errors
#


class DatabaseAccessError(Exception):
    pass


@register_exception
class InvalidAuthTokenError(errors.Unauthorized):

    """
    Exception raised when failing to get authorization for some action because
    the provided token either does not exist in the tokens database, has a
    distinct structure from the expected one, or is associated with a user
    with a distinct uuid than the one provided by the client.
    """

    wire_descrition = "invalid auth token"
    status = 401


#
# LockResource errors
#

@register_exception
class InvalidTokenError(SoledadError):

    """
    Exception raised when trying to unlock shared database with invalid token.
    """

    wire_description = "unlock unauthorized"
    status = 401


@register_exception
class NotLockedError(SoledadError):

    """
    Exception raised when trying to unlock shared database when it is not
    locked.
    """

    wire_description = "lock not found"
    status = 404


@register_exception
class AlreadyLockedError(SoledadError):

    """
    Exception raised when trying to lock shared database but it is already
    locked.
    """

    wire_description = "lock is locked"
    status = 403


@register_exception
class LockTimedOutError(SoledadError):

    """
    Exception raised when timing out while trying to lock the shared database.
    """

    wire_description = "lock timed out"
    status = 408


@register_exception
class CouldNotObtainLockError(SoledadError):

    """
    Exception raised when timing out while trying to lock the shared database.
    """

    wire_description = "error obtaining lock"
    status = 500


#
# SoledadBackend errors
# u1db error statuses also have to be updated
http_errors.ERROR_STATUSES = set(
    http_errors.wire_description_to_status.values())


class InvalidURLError(Exception):

    """
    Exception raised when Soledad encounters a malformed URL.
    """


class BackendNotReadyError(SoledadError):
    """
    Generic exception raised when the backend is not ready to dispatch a client
    request.
    """
    wire_description = "backend not ready"
    status = 500
