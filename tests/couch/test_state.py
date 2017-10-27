import mock
import pytest

from leap.soledad.common.couch import CONFIG_DOC_ID
from leap.soledad.common.couch import SCHEMA_VERSION
from leap.soledad.common.couch import SCHEMA_VERSION_KEY
from leap.soledad.common.couch.state import _check_db_schema_version
from leap.soledad.common.couch.state import check_schema_versions
from uuid import uuid4

from leap.soledad.common.errors import WrongCouchSchemaVersionError
from leap.soledad.common.errors import MissingCouchConfigDocumentError
from test_soledad.util import CouchDBTestCase

from twisted.internet import defer
from twisted.internet import reactor
from twisted.web.client import HTTPConnectionPool, Agent


class CouchDesignDocsTests(CouchDBTestCase):

    def setUp(self):
        CouchDBTestCase.setUp(self)
        self.db = self.couch_server.create('user-' + uuid4().hex)
        self.addCleanup(self.delete_db, self.db.name)
        self.pool = HTTPConnectionPool(reactor, persistent=False)
        self.agent = Agent(reactor, pool=self.pool)

    @defer.inlineCallbacks
    def tearDown(self):
        yield self.pool.closeCachedConnections()

    @defer.inlineCallbacks
    def test__check_db_schema_version_wrong_schema_version_raises(self):
        wrong_schema_version = SCHEMA_VERSION + 1
        self.db.create(
            {'_id': CONFIG_DOC_ID, SCHEMA_VERSION_KEY: wrong_schema_version})
        with pytest.raises(WrongCouchSchemaVersionError):
            yield _check_db_schema_version(
                self.couch_url, self.db.name, None, agent=self.agent)

    @defer.inlineCallbacks
    def test_check_schema_versions_wrong_schema_version_stops_reactor(self):
        wrong_schema_version = SCHEMA_VERSION + 1
        self.db.create(
            {'_id': CONFIG_DOC_ID, SCHEMA_VERSION_KEY: wrong_schema_version})
        mocked_reactor = mock.Mock()
        yield check_schema_versions(
            self.couch_url, agent=self.agent, reactor=mocked_reactor)
        mocked_reactor.stop.assert_called()

    @defer.inlineCallbacks
    def test__check_db_schema_version_missing_config_doc_raises(self):
        self.db.create({})
        with pytest.raises(MissingCouchConfigDocumentError):
            yield _check_db_schema_version(
                self.couch_url, self.db.name, None, agent=self.agent)

    @defer.inlineCallbacks
    def test_check_schema_versions_missing_config_doc_stops_reactor(self):
        self.db.create({})
        mocked_reactor = mock.Mock()
        yield check_schema_versions(
            self.couch_url, agent=self.agent, reactor=mocked_reactor)
        mocked_reactor.stop.assert_called()
