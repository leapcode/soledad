# -*- coding: utf-8 -*-
# server_state.py
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
State for servers to be used in tests.
"""


import os
import errno
import tempfile


from leap.soledad.common.l2db.remote.server_state import ServerState
from leap.soledad.common.tests.util import (
    copy_sqlcipher_database_for_test,
)


class ServerStateForTests(ServerState):

    """Passed to a Request when it is instantiated.

    This is used to track server-side state, such as working-directory, open
    databases, etc.
    """

    def __init__(self):
        self._workingdir = tempfile.mkdtemp()

    def _relpath(self, relpath):
        return os.path.join(self._workingdir, relpath)

    def open_database(self, path):
        """Open a database at the given location."""
        from leap.soledad.client.sqlcipher import SQLCipherDatabase
        return SQLCipherDatabase.open_database(path, '123', False)

    def create_database(self, path):
        """Create a database at the given location."""
        from leap.soledad.client.sqlcipher import SQLCipherDatabase
        return SQLCipherDatabase.open_database(path, '123', True)

    def check_database(self, path):
        """Check if the database at the given location exists.

        Simply returns if it does or raises DatabaseDoesNotExist.
        """
        db = self.open_database(path)
        db.close()

    def ensure_database(self, path):
        """Ensure database at the given location."""
        from leap.soledad.client.sqlcipher import SQLCipherDatabase
        full_path = self._relpath(path)
        db = SQLCipherDatabase.open_database(full_path, '123', False)
        return db, db._replica_uid

    def delete_database(self, path):
        """Delete database at the given location."""
        from leap.u1db.backends import sqlite_backend
        full_path = self._relpath(path)
        sqlite_backend.SQLiteDatabase.delete_database(full_path)

    def _copy_database(self, db):
        return copy_sqlcipher_database_for_test(None, db)
