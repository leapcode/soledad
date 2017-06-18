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

from .l2db import errors
from .l2db.remote import http_errors


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


class WrongCouchSchemaVersionError(SoledadError):
    """
    Raised in case there is a user database with wrong couch schema version.
    """


class MissingCouchConfigDocumentError(SoledadError):
    """
    Raised if a database has documents but lacks the couch config document.
    """
