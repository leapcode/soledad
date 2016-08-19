# conftest.py

"""
Provide a couch database with content stored in old schema.
"""

import couchdb
import pytest
import uuid


COUCH_URL = 'http://127.0.0.1:5984'

transaction_map = """
function(doc) {
    if (doc.u1db_transactions)
        doc.u1db_transactions.forEach(function(t) {
            emit(t[0],  // use timestamp as key so the results are ordered
                 t[1]); // value is the transaction_id
        });
}
"""

initial_docs = [
    {'_id': 'u1db_config', 'replica_uid': 'an-uid'},
    {'_id': 'u1db_sync_A', 'generation': 0, 'replica_uid': 'A',
     'transaction_id': ''},
    {'_id': 'u1db_sync_B', 'generation': 2, 'replica_uid': 'B',
     'transaction_id': 'X'},
    {'_id': 'doc1', 'u1db_transactions': [(1, 'trans-1'), (3, 'trans-3')]},
    {'_id': 'doc2', 'u1db_transactions': [(2, 'trans-2'), (4, 'trans-4')]},
    {'_id': '_design/docs'},
    {'_id': '_design/syncs'},
    {'_id': '_design/transactions',
     'views': {'log': {'map': transaction_map}}},
    # the following should be removed if found in the dbs
    {'_id': 'u1db_sync_log'},
    {'_id': 'u1db_sync_state'},
]


@pytest.fixture(scope='function')
def db(request):
    server = couchdb.Server(COUCH_URL)
    dbname = "user-" + uuid.uuid4().hex
    db = server.create(dbname)
    for doc in initial_docs:
        db.save(doc)
    request.addfinalizer(lambda: server.delete(dbname))
    return db
