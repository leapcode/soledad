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

@register_exception
class MissingAuthTokenError(errors.Unauthorized):
    """
    Exception raised when failing to get authorization for some action because
    the auth token is missing in the tokens db.
    """

    wire_description = "missing token"
    status = 401

@register_exception
class InvalidAuthTokenError(errors.Unauthorized):
    """
    Exception raised when failing to get authorization for some action because
    the provided token is different from the one in the tokens db.
    """

    wire_descrition = "token mismatch"
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
# CouchDatabase errors
#

@register_exception
class MissingDesignDocError(SoledadError):
    """
    Raised when trying to access a missing couch design document.
    """

    wire_description = "missing design document"
    status = 500


@register_exception
class MissingDesignDocNamedViewError(SoledadError):
    """
    Raised when trying to access a missing named view on a couch design
    document.
    """

    wire_description = "missing design document named function"
    status = 500


@register_exception
class MissingDesignDocListFunctionError(SoledadError):
    """
    Raised when trying to access a missing list function on a couch design
    document.
    """

    wire_description = "missing design document list function"
    status = 500


@register_exception
class MissingDesignDocDeletedError(SoledadError):
    """
    Raised when trying to access a deleted couch design document.
    """

    wire_description = "design document was deleted"
    status = 500


@register_exception
class DesignDocUnknownError(SoledadError):
    """
    Raised when trying to access a couch design document and getting an
    unknown error.
    """

    wire_description = "missing design document unknown error"
    status = 500


# u1db error statuses also have to be updated
http_errors.ERROR_STATUSES = set(
    http_errors.wire_description_to_status.values())
