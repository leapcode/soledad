import json
import pytest

from leap.soledad.client import crypto as old_crypto
from leap.soledad.common.couch import CouchDatabase
from leap.soledad.common import crypto as common_crypto

from test_soledad.u1db_tests import simple_doc


def deprecate_client_crypto(client):
    secret = client._crypto.secret
    _crypto = old_crypto.SoledadCrypto(secret)
    setattr(client._dbsyncer, '_crypto', _crypto)
    return client


def couch_database(couch_url, uuid):
    db = CouchDatabase(couch_url, "user-%s" % (uuid,))
    return db


@pytest.inlineCallbacks
def test_touch_updates_remote_representation(
        soledad_client, request):

    client = soledad_client()
    deprecated_client = deprecate_client_crypto(soledad_client())

    couch_url = request.config.option.couch_url
    remote = couch_database(couch_url, client._uuid)

    # ensure remote db is empty
    gen, docs = remote.get_all_docs()
    assert gen == 0
    assert len(docs) == 0

    # create a doc with deprecated client and sync
    yield deprecated_client.create_doc(json.loads(simple_doc))
    yield deprecated_client.sync()

    # check for doc in remote db
    gen, docs = remote.get_all_docs()
    assert gen == 1
    assert len(docs) == 1
    doc = docs.pop()
    content = doc.content
    assert common_crypto.ENC_JSON_KEY in content
    assert common_crypto.ENC_SCHEME_KEY in content
    assert common_crypto.ENC_METHOD_KEY in content
    assert common_crypto.ENC_IV_KEY in content
    assert common_crypto.MAC_KEY in content
    assert common_crypto.MAC_METHOD_KEY in content

    # "touch" the document with a newer client and synx
    _, docs = yield client.get_all_docs()
    yield client.put_doc(doc)
    yield client.sync()

    # check for newer representation of doc in remote db
    gen, docs = remote.get_all_docs()
    assert gen == 2
    assert len(docs) == 1
    doc = docs.pop()
    content = doc.content
    assert len(content) == 1
    assert 'raw' in content
