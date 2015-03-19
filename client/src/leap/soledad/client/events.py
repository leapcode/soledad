# -*- coding: utf-8 -*-
# signal.py
# Copyright (C) 2014 LEAP
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
Signaling functions.
"""


from leap.common import events
from leap.common.events import signal


SOLEDAD_CREATING_KEYS = events.proto.SOLEDAD_CREATING_KEYS
SOLEDAD_DONE_CREATING_KEYS = events.proto.SOLEDAD_DONE_CREATING_KEYS
SOLEDAD_DOWNLOADING_KEYS = events.proto.SOLEDAD_DOWNLOADING_KEYS
SOLEDAD_DONE_DOWNLOADING_KEYS = \
    events.proto.SOLEDAD_DONE_DOWNLOADING_KEYS
SOLEDAD_UPLOADING_KEYS = events.proto.SOLEDAD_UPLOADING_KEYS
SOLEDAD_DONE_UPLOADING_KEYS = \
    events.proto.SOLEDAD_DONE_UPLOADING_KEYS
SOLEDAD_NEW_DATA_TO_SYNC = events.proto.SOLEDAD_NEW_DATA_TO_SYNC
SOLEDAD_DONE_DATA_SYNC = events.proto.SOLEDAD_DONE_DATA_SYNC
SOLEDAD_SYNC_SEND_STATUS = events.proto.SOLEDAD_SYNC_SEND_STATUS
SOLEDAD_SYNC_RECEIVE_STATUS = events.proto.SOLEDAD_SYNC_RECEIVE_STATUS


__all__ = [
    "events",
    "signal",
    "SOLEDAD_CREATING_KEYS",
    "SOLEDAD_DONE_CREATING_KEYS",
    "SOLEDAD_DOWNLOADING_KEYS",
    "SOLEDAD_DONE_DOWNLOADING_KEYS",
    "SOLEDAD_UPLOADING_KEYS",
    "SOLEDAD_DONE_UPLOADING_KEYS",
    "SOLEDAD_NEW_DATA_TO_SYNC",
    "SOLEDAD_DONE_DATA_SYNC",
    "SOLEDAD_SYNC_SEND_STATUS",
    "SOLEDAD_SYNC_RECEIVE_STATUS",
]
