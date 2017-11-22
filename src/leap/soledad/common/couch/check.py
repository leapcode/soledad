# -*- coding: utf-8 -*-
# check.py
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
Database schema version verification
"""

import treq

from six.moves.urllib.parse import urljoin
from twisted.internet import defer
from urlparse import urlsplit

from leap.soledad.common.couch import CONFIG_DOC_ID
from leap.soledad.common.couch import SCHEMA_VERSION
from leap.soledad.common.couch import SCHEMA_VERSION_KEY
from leap.soledad.common.errors import WrongCouchSchemaVersionError
from leap.soledad.common.errors import MissingCouchConfigDocumentError
from leap.soledad.common.log import getLogger


logger = getLogger(__name__)


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
        if SCHEMA_VERSION_KEY not in config_doc:
            logger.error(
                "Database has config document but no schema version: %s" % db)
            raise WrongCouchSchemaVersionError(db)
        if config_doc[SCHEMA_VERSION_KEY] != SCHEMA_VERSION:
            logger.error(
                "Unsupported database schema in database: %s" % db)
            raise WrongCouchSchemaVersionError(db)


@defer.inlineCallbacks
def check_schema_versions(couch_url, agent=None):
    """
    Check that all user databases use the correct couch schema.

    :param couch_url: The URL for the couch database.
    :type couch_url: str
    :param agent: an optional agent for doing requests, used in tests.
    :type agent: twisted.web.client.Agent
    """
    url = urlsplit(couch_url)
    auth = (url.username, url.password) if url.username else None
    url = "%s://%s:%d" % (url.scheme, url.hostname, url.port)
    try:
        res = yield treq.get(urljoin(url, '_all_dbs'), auth=auth, agent=agent)
        dbs = yield res.json()
    except Exception as e:
        logger.error('Error trying to get list of dbs from %s: %r'
                     % (url, e))
        raise e
    deferreds = []
    semaphore = defer.DeferredSemaphore(20)
    logger.info('Starting CouchDB schema versions check...')
    for db in dbs:
        if not db.startswith('user-'):
            continue
        d = semaphore.run(_check_db_schema_version, url, db, auth, agent=agent)
        deferreds.append(d)
    d = defer.gatherResults(deferreds, consumeErrors=True)
    try:
        yield d
        logger.info('Finished CouchDB schema versions check.')
    except Exception as e:
        msg = 'Error checking CouchDB schema versions: %r' % e
        logger.error(msg)
        raise Exception(msg)
