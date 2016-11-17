import pytest

from leap.soledad.common.couch import CONFIG_DOC_ID
from leap.soledad.common.couch import SCHEMA_VERSION
from leap.soledad.common.couch import SCHEMA_VERSION_KEY
from leap.soledad.common.couch.state import CouchServerState

from leap.soledad.common.errors import WrongCouchSchemaVersionError
from leap.soledad.common.errors import MissingCouchConfigDocumentError


def test_wrong_couch_version_raises(db):
    wrong_schema_version = SCHEMA_VERSION + 1
    db.database.create(
        {'_id': CONFIG_DOC_ID, SCHEMA_VERSION_KEY: wrong_schema_version})
    with pytest.raises(WrongCouchSchemaVersionError):
        CouchServerState(db.couch_url, create_cmd='/bin/echo',
                         check_schema_versions=True)


def test_missing_config_doc_raises(db):
    db.database.create({})
    with pytest.raises(MissingCouchConfigDocumentError):
        CouchServerState(db.couch_url, create_cmd='/bin/echo',
                         check_schema_versions=True)
