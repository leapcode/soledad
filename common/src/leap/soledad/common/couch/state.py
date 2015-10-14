# -*- coding: utf-8 -*-
# state.py
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
Server state using CouchDatabase as backend.
"""
import re
import logging
from urlparse import urljoin

from u1db.remote.server_state import ServerState
from leap.soledad.common.command import exec_validated_cmd
from leap.soledad.common.couch import CouchDatabase
from u1db.errors import Unauthorized


logger = logging.getLogger(__name__)


def is_db_name_valid(name):
    """
    Validate a user database using a regular expression.

    :param name: database name.
    :type name: str

    :return: boolean for name vailidity
    :rtype: bool
    """
    db_name_regex = "^user-[a-f0-9]+$"
    return re.match(db_name_regex, name) is not None


class CouchServerState(ServerState):

    """
    Inteface of the WSGI server with the CouchDB backend.
    """

    def __init__(self, couch_url, create_cmd=None):
        """
        Initialize the couch server state.

        :param couch_url: The URL for the couch database.
        :type couch_url: str
        """
        self.couch_url = couch_url
        self.create_cmd = create_cmd

    def open_database(self, dbname):
        """
        Open a couch database.

        :param dbname: The name of the database to open.
        :type dbname: str

        :return: The SoledadBackend object.
        :rtype: SoledadBackend
        """
        url = urljoin(self.couch_url, dbname)
        db = CouchDatabase.open_database(url, create=False, ensure_ddocs=False)
        return db

    def ensure_database(self, dbname):
        """
        Ensure couch database exists.

        :param dbname: The name of the database to ensure.
        :type dbname: str

        :raise Unauthorized: If disabled or other error was raised.

        :return: The SoledadBackend object and its replica_uid.
        :rtype: (SoledadBackend, str)
        """
        if not self.create_cmd:
            raise Unauthorized()
        else:
            code, out = exec_validated_cmd(self.create_cmd, dbname,
                                           validator=is_db_name_valid)
            if code is not 0:
                logger.error("""
                    Error while creating database (%s) with (%s) command.
                    Output: %s
                    Exit code: %d
                    """ % (dbname, self.create_cmd, out, code))
                raise Unauthorized()
        db = self.open_database(dbname)
        return db, db.replica_uid

    def delete_database(self, dbname):
        """
        Delete couch database.

        :param dbname: The name of the database to delete.
        :type dbname: str

        :raise Unauthorized: Always, because Soledad server is not allowed to
                             delete databases.
        """
        raise Unauthorized()
