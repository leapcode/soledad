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
import re
import os
import treq

from six.moves.urllib.parse import urljoin
from twisted.internet import defer
from urlparse import urlsplit

from twisted.internet import reactor

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


#
# Database schema version verification
#

@defer.inlineCallbacks
def _check_db_schema_version(url, db, auth, agent=None):
    """
    Check if the schema version is up to date for a given database.

    :param url: the server base URL.
    :type url: str
    :param db: the database name.
    :type db: str
    :param auth: a tuple with (username, password) for acessing CouchDB.
    :type auth: tuple(str, str)
    :param agent: an optional agent for doing requests, used in tests.
    :type agent: twisted.web.client.Agent

    :raise MissingCouchConfigDocumentError: raised when a database is not empty
                                            but has no config document in it.

    :raise WrongCouchSchemaVersionError: raised when a config document was
                                         found but the schema version is
                                         different from what is expected.
    """
    # if there are documents, ensure that a config doc exists
    db_url = urljoin(url, '%s/' % db)
    config_doc_url = urljoin(db_url, CONFIG_DOC_ID)
    res = yield treq.get(config_doc_url, auth=auth, agent=agent)

    if res.code != 200 and res.code != 404:
        raise Exception("Unexpected HTTP response code: %d" % res.code)

    elif res.code == 404:
        res = yield treq.get(urljoin(db_url, '_all_docs'), auth=auth,
                             params={'limit': 1}, agent=agent)
        docs = yield res.json()
        if docs['total_rows'] != 0:
            logger.error(
                "Missing couch config document in database %s" % db)
            raise MissingCouchConfigDocumentError(db)

    elif res.code == 200:
        config_doc = yield res.json()
        if config_doc[SCHEMA_VERSION_KEY] != SCHEMA_VERSION:
            logger.error(
                "Unsupported database schema in database %s" % db)
            raise WrongCouchSchemaVersionError(db)


def _stop(failure, reactor):
    logger.error("Failure while checking schema versions: %r - %s"
                 % (failure, failure.message))
    reactor.addSystemEventTrigger('after', 'shutdown', os._exit, 1)
    reactor.stop()


@defer.inlineCallbacks
def check_schema_versions(couch_url, agent=None, reactor=reactor):
    """
    Check that all user databases use the correct couch schema.

    :param couch_url: The URL for the couch database.
    :type couch_url: str
    :param agent: an optional agent for doing requests, used in tests.
    :type agent: twisted.web.client.Agent
    :param reactor: an optional reactor for stopping in case of errors, used
                    in tests.
    :type reactor: twisted.internet.base.ReactorBase
    """
    url = urlsplit(couch_url)
    auth = (url.username, url.password) if url.username else None
    url = "%s://%s:%d" % (url.scheme, url.hostname, url.port)
    res = yield treq.get(urljoin(url, '_all_dbs'), auth=auth, agent=agent)
    dbs = yield res.json()
    deferreds = []
    semaphore = defer.DeferredSemaphore(20)
    for db in dbs:
        if not db.startswith('user-'):
            continue
        d = semaphore.run(_check_db_schema_version, url, db, auth, agent=agent)
        d.addErrback(_stop, reactor=reactor)
        deferreds.append(d)
    d = defer.gatherResults(deferreds, consumeErrors=True)
    yield d


#
# CouchDB Server state
#

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
        :param create_cmd: Command to be executed for user db creation. It will
                           receive a properly sanitized parameter with user db
                           name and should access CouchDB with necessary
                           privileges, which server lacks for security reasons.
        :type create_cmd: str
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
