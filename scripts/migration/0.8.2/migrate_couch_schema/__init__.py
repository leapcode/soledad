# __init__.py
"""
Support functions for migration script.
"""

import logging

from couchdb import Server
from couchdb import ResourceNotFound
from couchdb import ResourceConflict

from leap.soledad.common.couch import GENERATION_KEY
from leap.soledad.common.couch import TRANSACTION_ID_KEY
from leap.soledad.common.couch import REPLICA_UID_KEY
from leap.soledad.common.couch import DOC_ID_KEY
from leap.soledad.common.couch import SCHEMA_VERSION_KEY
from leap.soledad.common.couch import CONFIG_DOC_ID
from leap.soledad.common.couch import SYNC_DOC_ID_PREFIX
from leap.soledad.common.couch import SCHEMA_VERSION


logger = logging.getLogger(__name__)


#
# support functions
#

def _get_couch_server(couch_url):
    return Server(couch_url)


def _is_migrateable(db):
    config_doc = db.get('u1db_config')
    if config_doc is None:
        return False
    return True


def _get_transaction_log(db):
    ddoc_path = ['_design', 'transactions', '_view', 'log']
    resource = db.resource(*ddoc_path)
    try:
        _, _, data = resource.get_json()
    except ResourceNotFound:
        logger.warning(
            'Missing transactions design document, '
            'can\'t get transaction log.')
        return []
    rows = data['rows']
    transaction_log = []
    gen = 1
    for row in rows:
        transaction_log.append((gen, row['id'], row['value']))
        gen += 1
    return transaction_log


def _get_user_dbs(server):
    user_dbs = filter(lambda dbname: dbname.startswith('user-'), server)
    return user_dbs


#
# migration main functions
#

def migrate(args, target_version):
    server = _get_couch_server(args.couch_url)
    logger.info('starting couch schema migration to %s...' % target_version)
    if not args.do_migrate:
        logger.warning('dry-run: no changes will be made to databases')
    user_dbs = _get_user_dbs(server)
    for dbname in user_dbs:
        db = server[dbname]
        if not _is_migrateable(db):
            logger.warning("skipping not migrateable user db: %s" % dbname)
            continue
        logger.info("starting migration of user db: %s" % dbname)
        try:
            _migrate_user_db(db, args.do_migrate)
            logger.info("finished migration of user db: %s" % dbname)
        except:
            logger.exception('Error migrating user db: %s' % dbname)
            logger.error('Continuing with next database.')
    logger.info('finished couch schema migration to %s' % target_version)


def _migrate_user_db(db, do_migrate):
    _migrate_transaction_log(db, do_migrate)
    _migrate_sync_docs(db, do_migrate)
    _delete_design_docs(db, do_migrate)
    _migrate_config_doc(db, do_migrate)


def _migrate_transaction_log(db, do_migrate):
    transaction_log = _get_transaction_log(db)
    for gen, doc_id, trans_id in transaction_log:
        gen_doc_id = 'gen-%s' % str(gen).zfill(10)
        doc = {
            '_id': gen_doc_id,
            GENERATION_KEY: gen,
            DOC_ID_KEY: doc_id,
            TRANSACTION_ID_KEY: trans_id,
        }
        logger.info('creating gen doc: %s' % (gen_doc_id))
        if do_migrate:
            try:
                db.save(doc)
            except ResourceConflict:
                # this gen document already exists. if documents are the same,
                # continue with migration.
                existing_doc = db.get(gen_doc_id)
                for key in [GENERATION_KEY, DOC_ID_KEY, TRANSACTION_ID_KEY]:
                    if existing_doc[key] != doc[key]:
                        raise


def _migrate_config_doc(db, do_migrate):
    old_doc = db['u1db_config']
    new_doc = {
        '_id': CONFIG_DOC_ID,
        REPLICA_UID_KEY: old_doc[REPLICA_UID_KEY],
        SCHEMA_VERSION_KEY: SCHEMA_VERSION,
    }
    logger.info("moving config doc: %s -> %s"
                % (old_doc['_id'], new_doc['_id']))
    if do_migrate:
        db.save(new_doc)
        db.delete(old_doc)


def _migrate_sync_docs(db, do_migrate):
    view = db.view(
        '_all_docs',
        startkey='u1db_sync',
        endkey='u1db_synd',
        include_docs='true')
    for row in view.rows:
        old_doc = row['doc']
        old_id = old_doc['_id']

        # older schemas used different documents with ids starting with
        # "u1db_sync" to store sync-related data:
        #
        #   - u1db_sync_log: was used to store the whole sync log.
        #   - u1db_sync_state: was used to store the sync state.
        #
        # if any of these documents exist in the current db, they are leftover
        # from previous migrations, and should just be removed.
        if old_id in ['u1db_sync_log', 'u1db_sync_state']:
            logger.info('removing leftover "u1db_sync_log" document...')
            if do_migrate:
                db.delete(old_doc)
            continue

        replica_uid = old_id.replace('u1db_sync_', '')
        new_id = "%s%s" % (SYNC_DOC_ID_PREFIX, replica_uid)
        new_doc = {
            '_id': new_id,
            GENERATION_KEY: old_doc['generation'],
            TRANSACTION_ID_KEY: old_doc['transaction_id'],
            REPLICA_UID_KEY: replica_uid,
        }
        logger.info("moving sync doc: %s -> %s" % (old_id, new_id))
        if do_migrate:
            db.save(new_doc)
            db.delete(old_doc)


def _delete_design_docs(db, do_migrate):
    for ddoc in ['docs', 'syncs', 'transactions']:
        doc_id = '_design/%s' % ddoc
        doc = db.get(doc_id)
        if doc:
            logger.info("deleting design doc: %s" % doc_id)
            if do_migrate:
                db.delete(doc)
        else:
            logger.warning("design doc not found: %s" % doc_id)
