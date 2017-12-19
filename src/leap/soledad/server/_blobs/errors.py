# -*- coding: utf-8 -*-
# _blobs/error.py
# Copyright (C) 2017 LEAP
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
Blobs errors.
"""


class BlobNotFound(Exception):
    """
    Raised when a blob is not found in data storage backend.
    """


class BlobExists(Exception):
    """
    Raised when a blob already exists in data storage backend.
    """


class QuotaExceeded(Exception):
    """
    Raised when the quota would be exceeded if an operation would be held.
    """


class ImproperlyConfiguredException(Exception):
    """
    Raised when there is a problem with the configuration of a backend.
    """


class RangeNotSatisfiable(Exception):
    """
    Raised when the Range: HTTP header was sent but the server doesn't know how
    to satisfy it.
    """
