import pytest

from twisted.internet.defer import gatherResults

from leap.soledad.common.couch import CouchDatabase
from leap.soledad.common.document import ServerDocument


content = ' ' * 10000


@pytest.inlineCallbacks
def test_upload(soledad_client, request):
    # create a bunch of local documents
    uploads = 100
    deferreds = []
    for i in xrange(uploads):
        d = soledad_client.create_doc({'upload': True, 'content': content})
        deferreds.append(d)
    yield gatherResults(deferreds)

    # synchronize
    yield soledad_client.sync()

    # check that documents reached the remote database
    url = request.config.getoption('--couch-url')
    remote = CouchDatabase(url, 'user-0')
    remote_count, _ = remote.get_all_docs()
    assert remote_count == uploads


@pytest.inlineCallbacks
def test_download(soledad_client, request):
    # create a bunch of remote documents
    downloads = 100
    url = request.config.getoption('--couch-url')
    remote = CouchDatabase(url, 'user-0')
    for i in xrange(downloads):
        doc = ServerDocument('doc-%d' % i, 'replica:1')
        doc.content = {'download': True, 'content': content}
        remote.save_document(None, doc, i)

    # synchronize
    yield soledad_client.sync()

    # check that documents reached the local database
    local_count, docs = yield soledad_client.get_all_docs()
    assert local_count == downloads
