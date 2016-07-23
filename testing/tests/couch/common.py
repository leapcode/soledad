from uuid import uuid4
from urlparse import urljoin
from couchdb.client import Server

from leap.soledad.common import couch
from leap.soledad.common.document import ServerDocument

from test_soledad import u1db_tests as tests


simple_doc = tests.simple_doc
nested_doc = tests.nested_doc


def make_couch_database_for_test(test, replica_uid):
    port = str(test.couch_port)
    dbname = ('test-%s' % uuid4().hex)
    db = couch.CouchDatabase.open_database(
        urljoin('http://localhost:' + port, dbname),
        create=True,
        replica_uid=replica_uid or 'test',
        ensure_ddocs=True)
    test.addCleanup(test.delete_db, dbname)
    return db


def copy_couch_database_for_test(test, db):
    port = str(test.couch_port)
    couch_url = 'http://localhost:' + port
    new_dbname = db._dbname + '_copy'
    new_db = couch.CouchDatabase.open_database(
        urljoin(couch_url, new_dbname),
        create=True,
        replica_uid=db._replica_uid or 'test')
    # copy all docs
    session = couch.Session()
    old_couch_db = Server(couch_url, session=session)[db._dbname]
    new_couch_db = Server(couch_url, session=session)[new_dbname]
    for doc_id in old_couch_db:
        doc = old_couch_db.get(doc_id)
        # bypass u1db_config document
        if doc_id == 'u1db_config':
            pass
        # copy design docs
        elif doc_id.startswith('_design'):
            del doc['_rev']
            new_couch_db.save(doc)
        # copy u1db docs
        elif 'u1db_rev' in doc:
            new_doc = {
                '_id': doc['_id'],
                'u1db_rev': doc['u1db_rev']
            }
            attachments = []
            if ('u1db_conflicts' in doc):
                new_doc['u1db_conflicts'] = doc['u1db_conflicts']
                for c_rev in doc['u1db_conflicts']:
                    attachments.append('u1db_conflict_%s' % c_rev)
            new_couch_db.save(new_doc)
            # save conflict data
            attachments.append('u1db_content')
            for att_name in attachments:
                att = old_couch_db.get_attachment(doc_id, att_name)
                if (att is not None):
                    new_couch_db.put_attachment(new_doc, att,
                                                filename=att_name)
        elif doc_id.startswith('gen-'):
            new_couch_db.save(doc)
    # cleanup connections to prevent file descriptor leaking
    return new_db


def make_document_for_test(test, doc_id, rev, content, has_conflicts=False):
    return ServerDocument(
        doc_id, rev, content, has_conflicts=has_conflicts)


COUCH_SCENARIOS = [
    ('couch', {'make_database_for_test': make_couch_database_for_test,
               'copy_database_for_test': copy_couch_database_for_test,
               'make_document_for_test': make_document_for_test, }),
]
