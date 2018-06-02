import pytest
import mock

from leap.soledad.common.couch import CONFIG_DOC_ID
from leap.soledad.common.couch import SCHEMA_VERSION
from leap.soledad.common.couch import SCHEMA_VERSION_KEY
from leap.soledad.common.couch.check import _check_db_schema_version
from leap.soledad.common.couch.check import check_schema_versions
from uuid import uuid4

from leap.soledad.common.errors import WrongCouchSchemaVersionError
from leap.soledad.common.errors import MissingCouchConfigDocumentError
from test_soledad.util import CouchDBTestCase

from twisted.internet import defer
from twisted.internet import reactor
from twisted.web.client import HTTPConnectionPool, Agent


def restricted_listing(function):
    @mock.patch('leap.soledad.common.couch.check.list_dbs')
    def _set_list(self, *args, **kwargs):
        args[-1].return_value = defer.succeed([self.db.name])
        return function(self)
    return _set_list


@pytest.mark.needs_couch
class CouchStateTests(CouchDBTestCase):

    def setUp(self):
        CouchDBTestCase.setUp(self)
        self.db = self.couch_server.create('user-' + uuid4().hex)
        self.addCleanup(self.delete_db, self.db.name)
        self.pool = HTTPConnectionPool(reactor, persistent=False)
        self.agent = Agent(reactor, pool=self.pool)

    @defer.inlineCallbacks
    def tearDown(self):
        yield self.pool.closeCachedConnections()

    @restricted_listing
    @defer.inlineCallbacks
    def test__check_db_schema_version_wrong_schema_version_raises(self):
        wrong_schema_version = SCHEMA_VERSION + 1
        self.db.create(
            {'_id': CONFIG_DOC_ID, SCHEMA_VERSION_KEY: wrong_schema_version})
        with pytest.raises(WrongCouchSchemaVersionError):
            yield _check_db_schema_version(
                self.couch_url, self.db.name, None, agent=self.agent)

    @restricted_listing
    @defer.inlineCallbacks
    def test_check_schema_versions_wrong_schema_version_raises(self):
        wrong_schema_version = SCHEMA_VERSION + 1
        self.db.create(
            {'_id': CONFIG_DOC_ID, SCHEMA_VERSION_KEY: wrong_schema_version})
        expected_msg = 'Error checking CouchDB schema versions: ' \
                       'FirstError.*WrongCouchSchemaVersionError()'
        with pytest.raises(Exception, match=expected_msg):
            yield check_schema_versions(self.couch_url, agent=self.agent)

    @restricted_listing
    @defer.inlineCallbacks
    def test__check_db_schema_version_missing_config_doc_raises(self):
        self.db.create({})
        with pytest.raises(MissingCouchConfigDocumentError):
            yield _check_db_schema_version(
                self.couch_url, self.db.name, None, agent=self.agent)

    @restricted_listing
    @defer.inlineCallbacks
    def test_check_schema_versions_missing_config_doc_raises(self):
        self.db.create({})
        expected_msg = 'Error checking CouchDB schema versions: ' \
                       'FirstError.*MissingCouchConfigDocumentError()'
        with pytest.raises(Exception, match=expected_msg):
            yield check_schema_versions(self.couch_url, agent=self.agent)
