# test_migrate.py

"""
Ensure that the migration script works!
"""

from migrate_couch_schema import _migrate_user_db

from leap.soledad.common.couch import GENERATION_KEY
from leap.soledad.common.couch import TRANSACTION_ID_KEY
from leap.soledad.common.couch import REPLICA_UID_KEY
from leap.soledad.common.couch import DOC_ID_KEY
from leap.soledad.common.couch import SCHEMA_VERSION_KEY
from leap.soledad.common.couch import CONFIG_DOC_ID
from leap.soledad.common.couch import SYNC_DOC_ID_PREFIX
from leap.soledad.common.couch import SCHEMA_VERSION


def test__migrate_user_db(db):
    _migrate_user_db(db, True)

    # we should find exactly 6 documents: 2 normal documents and 4 generation
    # documents
    view = db.view('_all_docs')
    assert len(view.rows) == 6

    # ensure that the ids of the documents we found on the database are correct
    doc_ids = map(lambda doc: doc.id, view.rows)
    assert 'doc1' in doc_ids
    assert 'doc2' in doc_ids
    assert 'gen-0000000001' in doc_ids
    assert 'gen-0000000002' in doc_ids
    assert 'gen-0000000003' in doc_ids
    assert 'gen-0000000004' in doc_ids

    # assert config doc contents
    config_doc = db.get(CONFIG_DOC_ID)
    assert config_doc[REPLICA_UID_KEY] == 'an-uid'
    assert config_doc[SCHEMA_VERSION_KEY] == SCHEMA_VERSION

    # assert sync docs contents
    sync_doc_A = db.get('%s%s' % (SYNC_DOC_ID_PREFIX, 'A'))
    assert sync_doc_A[GENERATION_KEY] == 0
    assert sync_doc_A[REPLICA_UID_KEY] == 'A'
    assert sync_doc_A[TRANSACTION_ID_KEY] == ''
    sync_doc_B = db.get('%s%s' % (SYNC_DOC_ID_PREFIX, 'B'))
    assert sync_doc_B[GENERATION_KEY] == 2
    assert sync_doc_B[REPLICA_UID_KEY] == 'B'
    assert sync_doc_B[TRANSACTION_ID_KEY] == 'X'

    # assert gen docs contents
    gen_1 = db.get('gen-0000000001')
    assert gen_1[DOC_ID_KEY] == 'doc1'
    assert gen_1[GENERATION_KEY] == 1
    assert gen_1[TRANSACTION_ID_KEY] == 'trans-1'
    gen_2 = db.get('gen-0000000002')
    assert gen_2[DOC_ID_KEY] == 'doc2'
    assert gen_2[GENERATION_KEY] == 2
    assert gen_2[TRANSACTION_ID_KEY] == 'trans-2'
    gen_3 = db.get('gen-0000000003')
    assert gen_3[DOC_ID_KEY] == 'doc1'
    assert gen_3[GENERATION_KEY] == 3
    assert gen_3[TRANSACTION_ID_KEY] == 'trans-3'
    gen_4 = db.get('gen-0000000004')
    assert gen_4[DOC_ID_KEY] == 'doc2'
    assert gen_4[GENERATION_KEY] == 4
    assert gen_4[TRANSACTION_ID_KEY] == 'trans-4'
