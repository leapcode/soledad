# -*- coding: utf-8 -*-
# _blobs/state.py
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
Get handlers that implement IBlobsBackend given a backend name.
"""

from .errors import ImproperlyConfiguredException
from .fs_backend import FilesystemBlobsBackend


class BlobsServerState(object):
    """
    Given a backend name, it gives a instance of IBlobsBackend
    """
    # Allowed backend classes are defined here
    handlers = {"filesystem": FilesystemBlobsBackend}

    def __init__(self, backend, **backend_kwargs):
        if backend not in self.handlers:
            raise ImproperlyConfiguredException("No such backend: %s", backend)
        self.backend = self.handlers[backend](**backend_kwargs)

    def open_database(self, user_id):
        """
        That method is just for compatibility with CouchServerState, so
        IncomingAPI can change backends.
        """
        # TODO: deprecate/refactor it as it's here for compatibility.
        return self.backend
