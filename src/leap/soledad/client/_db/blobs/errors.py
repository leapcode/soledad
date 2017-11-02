# -*- coding: utf-8 -*-
# errors.py
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
This module contains the different errors that can happen when dealing with
blobs.
"""
from leap.soledad.common.errors import SoledadError


class BlobAlreadyExistsError(SoledadError):
    """
    Raised on attempts to put local or remote blobs that already exist in
    storage.
    """


class BlobNotFoundError(SoledadError):
    """
    Raised on attemtps to get remote blobs that do not exist in storage.
    """


class InvalidFlagsError(SoledadError):
    """
    Raised on attempts to set invalid flags for remotelly stored blobs.
    """


class RetriableTransferError(Exception):
    """
    Raised for any blob transfer error that is considered retriable.
    """


class MaximumRetriesError(Exception):
    """
    Raised when the maximum number of transfer retries has been reached.
    """
