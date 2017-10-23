# -*- coding: utf-8 -*-
# state.py
# Copyright (C) 2015,2016 LEAP
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
import couchdb
import re

from six.moves.urllib.parse import urljoin

from leap.soledad.common.log import getLogger
from leap.soledad.common.couch import CouchDatabase
from leap.soledad.common.couch import CONFIG_DOC_ID
from leap.soledad.common.couch import SCHEMA_VERSION
from leap.soledad.common.couch import SCHEMA_VERSION_KEY
from leap.soledad.common.command import exec_validated_cmd
from leap.soledad.common.l2db.remote.server_state import ServerState
from leap.soledad.common.l2db.errors import Unauthorized
from leap.soledad.common.errors import WrongCouchSchemaVersionError
from leap.soledad.common.errors import MissingCouchConfigDocumentError


logger = getLogger(__name__)


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

    def __init__(self, couch_url, create_cmd=None,
                 check_schema_versions=False):
        """
        Initialize the couch server state.

        :param couch_url: The URL for the couch database.
        :type couch_url: str
        :param create_cmd: Command to be executed for user db creation. It will
                           receive a properly sanitized parameter with user db
                           name and should access CouchDB with necessary
                           privileges, which server lacks for security reasons.
        :type create_cmd: str
        :param check_schema_versions: Whether to check couch schema version of
                                      user dbs. Set to False as this is only
                                      intended to run once during start-up.
        :type check_schema_versions: bool
        """
        self.couch_url = couch_url
        self.create_cmd = create_cmd
        if check_schema_versions:
            self._check_schema_versions()

    def _check_schema_versions(self):
        """
        Check that all user databases use the correct couch schema.
        """
        server = couchdb.client.Server(self.couch_url)
        for dbname in server:
            if not dbname.startswith('user-'):
                continue
            db = server[dbname]

            # if there are documents, ensure that a config doc exists
            config_doc = db.get(CONFIG_DOC_ID)
            if config_doc:
                if config_doc[SCHEMA_VERSION_KEY] != SCHEMA_VERSION:
                    logger.error(
                        "Unsupported database schema in database %s" % dbname)
                    raise WrongCouchSchemaVersionError(dbname)
            else:
                result = db.view('_all_docs', limit=1)
                if result.total_rows != 0:
                    logger.error(
                        "Missing couch config document in database %s"
                        % dbname)
                    raise MissingCouchConfigDocumentError(dbname)

    def open_database(self, dbname):
        """
        Open a couch database.

        :param dbname: The name of the database to open.
        :type dbname: str

        :return: The SoledadBackend object.
        :rtype: SoledadBackend
        """
        url = urljoin(self.couch_url, dbname)
        db = CouchDatabase.open_database(url, create=False)
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
