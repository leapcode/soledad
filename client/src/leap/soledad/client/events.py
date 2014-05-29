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


SOLEDAD_CREATING_KEYS = 'Creating keys...'
SOLEDAD_DONE_CREATING_KEYS = 'Done creating keys.'
SOLEDAD_DOWNLOADING_KEYS = 'Downloading keys...'
SOLEDAD_DONE_DOWNLOADING_KEYS = 'Done downloading keys.'
SOLEDAD_UPLOADING_KEYS = 'Uploading keys...'
SOLEDAD_DONE_UPLOADING_KEYS = 'Done uploading keys.'
SOLEDAD_NEW_DATA_TO_SYNC = 'New data available.'
SOLEDAD_DONE_DATA_SYNC = 'Done data sync.'
SOLEDAD_SYNC_SEND_STATUS = 'Sync: sent one document.'
SOLEDAD_SYNC_RECEIVE_STATUS = 'Sync: received one document.'

# we want to use leap.common.events to emits signals, if it is available.
try:
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

except ImportError:
    # we define a fake signaling function and fake signal constants that will
    # allow for logging signaling attempts in case leap.common.events is not
    # available.

    def signal(signal, content=""):
        logger.info("Would signal: %s - %s." % (str(signal), content))
