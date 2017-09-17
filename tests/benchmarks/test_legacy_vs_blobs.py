# "Legacy" versus "Incoming blobs" pipeline comparison
# ====================================================
#
# This benchmarking aims to compare the legacy and new mail incoming pipeline,
# to asses performance improvements brought by the introduction of blobs.
#
# We use the following sizes in these tests:
#
#   - headers:  4   KB
#   - metadata: 0.1 KB
#   - flags:    0.5 KB
#   - content:  variable
#
# "Legacy" incoming mail pipeline:
#
#   - email arrives at MX.
#   - MX encrypts to public key and puts into couch.
#   - pubkey encrypted doc is synced to soledad client as "incoming".
#   - bitmask mail processes "incoming" and generates 3 metadocs + 1 payload
#     doc per message.
#   - soledad client syncs 4 documents back to server.
#
# "Incoming blobs" mail pipeline:
#
#   - email arrives at MX.
#   - MX encyrpts to public key and puts into soledad server.
#   - soledad server writes a blob to filesystem.
#   - soledad client gets the incoming blob from server and generates 3
#     metadocs + 1 blob.
#   - soledad client syncs 3 meta documents and 1 blob back to server.
#
# Some notes about the tests in this file:
#
#   - This is a simulation of the legacy and new incoming mail pipelines.
#     There is no actual mail processing operation done (i.e. no pubkey crypto,
#     no mail parsing), only usual soledad document manipulation and sync (with
#     local 1network and crypto).
#
#   - Each test simulates a whole incoming mail pipeline, including get new
#     incoming messages from server, create new documents that represent the
#     parsed message, and synchronize those back to the server.
#
#   - These tests are disabled by default because it doesn't make much sense to
#     have them run automatically for all commits in the repository. Instead,
#     we will run them manually for specific releases and store results and
#     analisys in a subfolder.

import base64
import pytest
import random
import sys
import treq
import uuid

from io import BytesIO

from twisted.internet.defer import gatherResults
from twisted.internet.defer import returnValue
from twisted.internet.defer import DeferredSemaphore

from leap.soledad.common.blobs import Flags
from leap.soledad.client._db.blobs import BlobDoc


def payload(size):
    random.seed(1337)  # same seed to avoid different bench results
    payload_bytes = bytearray(random.getrandbits(8) for _ in xrange(size))
    # encode as base64 to avoid ascii encode/decode errors
    return base64.b64encode(payload_bytes)[:size]  # remove b64 overhead


PARTS = {
    'headers': payload(4000),
    'metadata': payload(100),
    'flags': payload(500),
}


#
# "Legacy" incoming mail pipeline.
#

@pytest.inlineCallbacks
def load_up_legacy(client, amount, content):
    # make sure there are no document from previous runs
    yield client.sync()
    _, docs = yield client.get_all_docs()
    deferreds = []
    for doc in docs:
        d = client.delete_doc(doc)
        deferreds.append(d)
    yield gatherResults(deferreds)
    yield client.sync()

    # create a bunch of local documents representing email messages
    deferreds = []
    for i in xrange(amount):
        deferreds.append(client.create_doc(content))
    yield gatherResults(deferreds)
    yield client.sync()


@pytest.inlineCallbacks
def process_incoming_docs(client, docs):
    deferreds = []
    for doc in docs:

        # create fake documents that represent message
        for name in PARTS.keys():
            d = client.create_doc({name: doc.content[name]})
            deferreds.append(d)

        # create one document with content
        key = 'content'
        d = client.create_doc({key: doc.content[key]})
        deferreds.append(d)

        # delete the old incoming document
        d = client.delete_doc(doc)
        deferreds.append(d)

    # wait for all operatios to succeed
    yield gatherResults(deferreds)


def create_legacy_test(amount, size):
    group = 'test_legacy_vs_blobs_%d_%dk' % (amount, (size / 1000))

    @pytest.inlineCallbacks
    @pytest.mark.skip(reason="avoid running for all commits")
    @pytest.mark.benchmark(group=group)
    def test(soledad_client, txbenchmark_with_setup):
        client = soledad_client()

        # setup the content of initial documents representing incoming emails
        content = {'content': payload(size), 'incoming': True}
        for name, data in PARTS.items():
            content[name] = data

        @pytest.inlineCallbacks
        def setup():
            yield load_up_legacy(client, amount, content)
            clean_client = soledad_client(force_fresh_db=True)
            yield clean_client.create_index('incoming', 'bool(incoming)')
            returnValue(clean_client)

        @pytest.inlineCallbacks
        def legacy_pipeline(client):
            yield client.sync()
            docs = yield client.get_from_index('incoming', '1')
            yield process_incoming_docs(client, docs)
            yield client.sync()

        yield txbenchmark_with_setup(setup, legacy_pipeline)
    return test


# ATTENTION: update the documentation in ../docs/benchmarks.rst if you change
# the number of docs or the doc sizes for the tests below.
test_legacy_10_1000k = create_legacy_test(10, 1000 * 1000)
test_legacy_100_100k = create_legacy_test(100, 100 * 1000)
test_legacy_1000_10k = create_legacy_test(1000, 10 * 1000)


#
# "Incoming blobs" mail pipeline:
#

# used to limit the amount of concurrent accesses to the blob manager
semaphore = DeferredSemaphore(2)


# deliver data to a user by using the incoming api at given url.
def deliver_using_incoming_api(url, user_uuid, token, data):
    auth = 'Token %s' % base64.b64encode('%s:%s' % (user_uuid, token))
    uri = "%s/incoming/%s/%s?namespace=MX" % (url, user_uuid, uuid.uuid4().hex)
    return treq.put(uri, headers={'Authorization': auth}, data=BytesIO(data))


# deliver data to a user by faking incoming using blobs
@pytest.inlineCallbacks
def deliver_using_blobs(client, fd):
    # put
    blob_id = uuid.uuid4().hex
    doc = BlobDoc(fd, blob_id=blob_id)
    size = sys.getsizeof(fd)
    yield client.blobmanager.put(doc, size, namespace='MX')
    # and flag
    flags = [Flags.PENDING]
    yield client.blobmanager.set_flags(blob_id, flags, namespace='MX')


def reclaim_free_space(client):
    return client.blobmanager.local.dbpool.runQuery("VACUUM")


@pytest.inlineCallbacks
def load_up_blobs(client, amount, data):
    # make sure there are no document from previous runs
    yield client.sync()
    _, docs = yield client.get_all_docs()
    deferreds = []
    for doc in docs:
        d = client.delete_doc(doc)
        deferreds.append(d)
    yield gatherResults(deferreds)
    yield client.sync()

    # delete all payload from blobs db and server
    for namespace in ['MX', 'payload']:
        ids = yield client.blobmanager.remote_list(namespace=namespace)
        deferreds = []
        for blob_id in ids:
            d = semaphore.run(
                client.blobmanager.delete, blob_id, namespace=namespace)
            deferreds.append(d)
    yield gatherResults(deferreds)

    # create a bunch of incoming blobs
    deferreds = []
    for i in xrange(amount):
        # choose method of delivery based in test being local or remote
        if '127.0.0.1' in client.server_url:
            fun = deliver_using_incoming_api
            args = (client.server_url, client.uuid, client.token, data)
        else:
            fun = deliver_using_blobs
            args = (client, BytesIO(data))
        d = semaphore.run(fun, *args)
        deferreds.append(d)
    yield gatherResults(deferreds)

    # empty local blobs db
    yield client.blobmanager.local.dbpool.runQuery(
        "DELETE FROM blobs WHERE 1;")
    yield reclaim_free_space(client)


@pytest.inlineCallbacks
def process_incoming_blobs(client, pending):
    # process items
    deferreds = []
    for item in pending:
        d = process_one_incoming_blob(client, item)
        deferreds.append(d)
    yield gatherResults(deferreds)


@pytest.inlineCallbacks
def process_one_incoming_blob(client, item):
    fd = yield semaphore.run(
        client.blobmanager.get, item, namespace='MX')

    # create metadata docs
    deferreds = []
    for name, data in PARTS.items():
        d = client.create_doc({name: data})
        deferreds.append(d)

    # put the incoming blob as it would be done after mail processing
    doc = BlobDoc(fd, blob_id=uuid.uuid4().hex)
    size = sys.getsizeof(fd)
    d = semaphore.run(
        client.blobmanager.put, doc, size, namespace='payload')
    deferreds.append(d)
    yield gatherResults(deferreds)

    # delete incoming blob
    yield semaphore.run(
        client.blobmanager.delete, item, namespace='MX')


def create_blobs_test(amount, size):
    group = 'test_legacy_vs_blobs_%d_%dk' % (amount, (size / 1000))

    @pytest.inlineCallbacks
    @pytest.mark.skip(reason="avoid running for all commits")
    @pytest.mark.benchmark(group=group)
    def test(soledad_client, txbenchmark_with_setup):
        client = soledad_client()
        blob_payload = payload(size)

        @pytest.inlineCallbacks
        def setup():
            yield load_up_blobs(client, amount, blob_payload)
            returnValue(soledad_client(force_fresh_db=True))

        @pytest.inlineCallbacks
        def blobs_pipeline(client):
            pending = yield client.blobmanager.remote_list(
                namespace='MX', filter_flags=Flags.PENDING)
            yield process_incoming_blobs(client, pending)
            # reclaim_free_space(client)
            yield client.sync()
            yield client.blobmanager.send_missing(namespace='payload')

        yield txbenchmark_with_setup(setup, blobs_pipeline)
    return test


# ATTENTION: update the documentation in ../docs/benchmarks.rst if you change
# the number of docs or the doc sizes for the tests below.
test_blobs_10_1000k = create_blobs_test(10, 1000 * 1000)
test_blobs_100_100k = create_blobs_test(100, 100 * 1000)
test_blobs_1000_10k = create_blobs_test(1000, 10 * 1000)
