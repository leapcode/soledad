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


#
# LockResource: a lock based on a document in the shared database.
#

class InvalidTokenError(errors.U1DBError):
    """
    Exception raised when trying to unlock shared database with invalid token.
    """

    wire_description = "unlock unauthorized"
    status = 401


class NotLockedError(errors.U1DBError):
    """
    Exception raised when trying to unlock shared database when it is not
    locked.
    """

    wire_description = "lock not found"
    status = 404


class AlreadyLockedError(errors.U1DBError):
    """
    Exception raised when trying to lock shared database but it is already
    locked.
    """

    wire_description = "lock is locked"
    status = 403

# update u1db "wire description to status" and "wire description to exception"
# maps.
for e in [InvalidTokenError, NotLockedError, AlreadyLockedError]:
    http_errors.wire_description_to_status.update({
        e.wire_description: e.status})
    errors.wire_description_to_exc.update({
        e.wire_description: e})

# u1db error statuses also have to be updated
http_errors.ERROR_STATUSES = set(
    http_errors.wire_description_to_status.values())
