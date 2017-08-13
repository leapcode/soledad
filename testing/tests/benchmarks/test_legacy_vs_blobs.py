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
import sys
import treq
import uuid

from io import BytesIO

from twisted.internet.defer import gatherResults, returnValue

from leap.soledad.common.blobs import Flags
from leap.soledad.client._db.blobs import BlobDoc


PARTS_SIZES = {
    'headers': 4000,
    'metadata': 100,
    'flags': 500,
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


def create_legacy(downloads, size):
    @pytest.inlineCallbacks
    @pytest.mark.skip(reason="avoid running for all commits")
    @pytest.mark.benchmark(group="test_legacy_vs_blobs")
    def test(soledad_client, txbenchmark_with_setup, payload):
        client = soledad_client()

        content = {'content': payload(size), 'incoming': True}
        for n, s in PARTS_SIZES.items():
            content[n] = payload(s)

        @pytest.inlineCallbacks
        def setup():
            yield load_up_legacy(client, downloads, content)
            returnValue(soledad_client(force_fresh_db=True))

        @pytest.inlineCallbacks
        def legacy_pipeline(clean_client):

            # create indexes so we can later retrieve incoming docs
            yield clean_client.create_index('incoming', 'bool(incoming)')

            # receive all documents from server
            yield clean_client.sync()

            # get incoming documents
            docs = yield clean_client.get_from_index('incoming', '1')

            # process incoming documents
            deferreds = []
            for doc in docs:

                # create fake documents that represent message
                for name in PARTS_SIZES.keys():
                    d = clean_client.create_doc({name: doc.content[name]})
                    deferreds.append(d)

                # create one document with content
                key = 'content'
                d = clean_client.create_doc({key: doc.content[key]})
                deferreds.append(d)

                # delete the old incoming document
                d = clean_client.delete_doc(doc)
                deferreds.append(d)

            # wait for all operatios to succeed
            yield gatherResults(deferreds)

            # sync new documents back to server
            yield clean_client.sync()

        yield txbenchmark_with_setup(setup, legacy_pipeline)
    return test


# ATTENTION: update the documentation in ../docs/benchmarks.rst if you change
# the number of docs or the doc sizes for the tests below.
test_legacy_10_1000k = create_legacy(10, 1000 * 1000)
test_legacy_100_100k = create_legacy(100, 100 * 1000)
test_legacy_1000_10k = create_legacy(1000, 10 * 1000)


#
# "Incoming blobs" mail pipeline:
#

@pytest.inlineCallbacks
def deliver(url, user_uuid, token, payload):
    auth = 'Token %s' % base64.b64encode('%s:%s' % (user_uuid, token))
    uri = "%s/incoming/%s/%s?namespace=MX" % (url, user_uuid, uuid.uuid4().hex)
    yield treq.put(uri, headers={'Authorization': auth},
                   data=BytesIO(payload))


def should_brake(i):
    return ((i + 1) % 5) == 0


@pytest.inlineCallbacks
def load_up_blobs(client, amount, payload):
    # create a bunch of local documents representing email messages
    deferreds = []
    for i in xrange(amount):
        d = deliver(client.server_url, client.uuid, client.token, payload)
        deferreds.append(d)
        if should_brake(i):
            yield gatherResults(deferreds)
            deferreds = []
    yield gatherResults(deferreds)


def create_blobs(downloads, size):
    @pytest.inlineCallbacks
    @pytest.mark.skip(reason="avoid running for all commits")
    @pytest.mark.benchmark(group="test_legacy_vs_blobs")
    def test(soledad_client, txbenchmark_with_setup, payload):
        client = soledad_client()
        blob_payload = payload(size)

        @pytest.inlineCallbacks
        def setup():
            yield load_up_blobs(client, downloads, blob_payload)
            returnValue(soledad_client(force_fresh_db=True))

        @pytest.inlineCallbacks
        def blobs_pipeline(clean_client):

            # get list of pending incoming blobs
            pending = yield clean_client.blobmanager.remote_list(
                namespace='MX', filter_flags=Flags.PENDING)

            # download incoming blobs
            deferreds = []
            incoming = []
            i = 0
            for item in pending:
                d = clean_client.blobmanager.get(item, namespace='MX')
                deferreds.append(d)
                if should_brake(i):
                    incoming += yield gatherResults(deferreds)
                    deferreds = []
                i += 1
            incoming += yield gatherResults(deferreds)

            # create data on local client
            deferreds = []
            i = 0
            for item in incoming:
                for name, size in PARTS_SIZES.items():
                    d = clean_client.create_doc({name: payload(size)})
                    deferreds.append(d)
                doc = BlobDoc(item, blob_id=uuid.uuid4().hex)
                size = sys.getsizeof(item)
                d = clean_client.blobmanager.put(
                    doc, size, namespace='payload')
                deferreds.append(d)
                if should_brake(i):
                    gatherResults(deferreds)
                    deferreds = []
                i += 1
            yield gatherResults(deferreds)

            # delete incoming from server
            deferreds = []
            for item in pending:
                d = clean_client.blobmanager.delete(item, namespace='MX')
                deferreds.append(d)
            yield gatherResults(deferreds)

            # sync and send blobs in parallel
            deferreds = []
            d = clean_client.sync()
            deferreds.append(d)
            d = clean_client.blobmanager.send_missing(namespace='payload')
            deferreds.append(d)
            yield gatherResults(deferreds)

        yield txbenchmark_with_setup(setup, blobs_pipeline)
    return test


# ATTENTION: update the documentation in ../docs/benchmarks.rst if you change
# the number of docs or the doc sizes for the tests below.
test_blobs_10_1000k = create_blobs(10, 1000 * 1000)
test_blobs_100_100k = create_blobs(100, 100 * 1000)
test_blobs_1000_10k = create_blobs(1000, 10 * 1000)
