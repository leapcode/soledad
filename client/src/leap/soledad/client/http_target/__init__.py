# -*- coding: utf-8 -*-
# http_target.py
# Copyright (C) 2015 LEAP
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
A U1DB backend for encrypting data before sending to server and decrypting
after receiving.
"""


import logging

from leap.soledad.client.http_target.send import HTTPDocSender
from leap.soledad.client.http_target.api import SyncTargetAPI
from leap.soledad.client.http_target.fetch import HTTPDocFetcher


logger = logging.getLogger(__name__)


class SoledadHTTPSyncTarget(SyncTargetAPI, HTTPDocSender, HTTPDocFetcher):

    """
    A SyncTarget that encrypts data before sending and decrypts data after
    receiving.

    Normally encryption will have been written to the sync database upon
    document modification. The sync database is also used to write temporarily
    the parsed documents that the remote send us, before being decrypted and
    written to the main database.
    """
