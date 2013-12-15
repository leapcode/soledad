#!/usr/bin/python

import sys
import json
import logging
import argparse
import re
import threading
from urlparse import urlparse
from ConfigParser import ConfigParser
from couchdb.client import Server
from couchdb.http import ResourceNotFound, Resource, Session
from datetime import datetime

from leap.soledad.common.couch import CouchDatabase


# parse command line for the log file name
logger_fname = "/tmp/u1db-couch-db-migration_%s.log" % \
               str(datetime.now()).replace(' ', '_')
parser = argparse.ArgumentParser()
parser.add_argument('--log', action='store', default=logger_fname, type=str,
                    required=False, help='the name of the log file', nargs=1)
args = parser.parse_args()


# configure the logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
print "Logging to %s." % args.log
logging.basicConfig(
    filename=args.log,
    format="%(asctime)-15s %(message)s")


# configure threads
max_threads = 20
semaphore_pool = threading.BoundedSemaphore(value=max_threads)

# get couch url
cp = ConfigParser()
cp.read('/etc/leap/soledad-server.conf')
url = cp.get('soledad-server', 'couch_url')

resource = Resource(url, Session(retry_delays=[1,2,4,8], timeout=10))
server = Server(url=resource)

hidden_url = re.sub(
    'http://(.*):.*@',
    'http://\\1:xxxxx@',
    url)

print """
==========
ATTENTION!
==========

This script will modify Soledad's shared and user databases in:

  %s

This script does not make a backup of the couch db data, so make sure youj
have a copy or you may loose data.
""" % hidden_url
confirm = raw_input("Proceed (type uppercase YES)? ")

if confirm != "YES":
    exit(1)


#
# Thread
#

class DocWorkerThread(threading.Thread):

    def __init__(self, dbname, doc_id, db_idx, db_len, doc_idx, doc_len,
                 transaction_log, conflict_log, release_fun):
        threading.Thread.__init__(self)
        resource = Resource(url, Session(retry_delays=[1,2,4,8], timeout=10))
        server = Server(url=resource)
        self._dbname = dbname
        self._cdb = server[self._dbname]
        self._doc_id = doc_id
        self._db_idx = db_idx
        self._db_len = db_len
        self._doc_idx = doc_idx
        self._doc_len = doc_len
        self._transaction_log = transaction_log
        self._conflict_log = conflict_log
        self._release_fun = release_fun

    def run(self):

        old_doc = self._cdb[self._doc_id]

        # skip non u1db docs
        if 'u1db_rev' not in old_doc:
            logger.debug('(%d/%d) (%d/%d) Skipping %s/%s).' %
                         (self._db_idx, self._db_len, self._doc_idx,
                          self._doc_len, self._dbname, self._doc_id))
            self._release_fun()
            return
        else:
            logger.debug('(%d/%d) (%d/%d) Processing %s/%s ...' %
                         (self._db_idx, self._db_len, self._doc_idx,
                          self._doc_len, self._dbname, self._doc_id))

        doc = {
            '_id': self._doc_id,
            '_rev': old_doc['_rev'],
            'u1db_rev': old_doc['u1db_rev']
        }
        attachments = []

        # add transactions
        doc['u1db_transactions'] = map(
            lambda (gen, doc_id, trans_id): (gen, trans_id),
            filter(
                lambda (gen, doc_id, trans_id): doc_id == doc['_id'],
                self._transaction_log))
        if len(doc['u1db_transactions']) == 0:
            del doc['u1db_transactions']

        # add conflicts
        if doc['_id'] in self._conflict_log:
            attachments.append([
                conflict_log[doc['_id']],
                'u1db_conflicts',
                "application/octet-stream"])

        # move document's content to 'u1db_content' attachment
        content = self._cdb.get_attachment(doc, 'u1db_json')
        if content is not None:
            attachments.append([
                content,
                'u1db_content',
                "application/octet-stream"])
        #self._cdb.delete_attachment(doc, 'u1db_json')

        # save modified doc
        self._cdb.save(doc)

        # save all doc attachments
        for content, att_name, content_type in attachments:
            self._cdb.put_attachment(
                doc,
                content,
                filename=att_name,
                content_type=content_type)

        # release the semaphore
        self._release_fun()


db_idx = 0
db_len = len(server)
for dbname in server:

    db_idx += 1

    if not (dbname.startswith('user-') or dbname == 'shared') \
            or dbname == 'user-test-db':
        logger.info("(%d/%d) Skipping db %s." % (db_idx, db_len, dbname))
        continue

    logger.info("(%d/%d) Migrating db %s." % (db_idx, db_len, dbname))

    # get access to couch db
    cdb = Server(url)[dbname]

    # get access to soledad db
    sdb = CouchDatabase(url, dbname)

    # Migration table
    # ---------------
    #
    # * Metadata that was previously stored in special documents migrate to
    #   inside documents, to allow for atomic doc-and-metadata updates.
    # * Doc content attachment name changes.
    # * Indexes are removed, to be implemented in the future possibly as
    #   design docs view functions.
    #
    # +-----------------+-------------------------+-------------------------+
    # | Data            | old storage             | new storage             |
    # |-----------------+-------------------------+-------------------------+
    # | doc content     | <doc_id>/u1db_json      | <doc_id>/u1db_content   |
    # | doc conflicts   | u1db/_conflicts         | <doc_id>/u1db_conflicts |
    # | transaction log | u1db/_transaction_log   | doc.u1db_transactions   |
    # | sync log        | u1db/_other_generations | u1db_sync_log           |
    # | indexes         | u1db/_indexes           | not implemented         |
    # | replica uid     | u1db/_replica_uid       | u1db_config             |
    # +-----------------+-------------------------+-------------------------+

    def get_att_content(db, doc_id, att_name):
        try:
            return json.loads(
                db.get_attachment(
                    doc_id, att_name).read())['content']
        except:
            import ipdb
            ipdb.set_trace()

    # only migrate databases that have the 'u1db/_replica_uid' document
    try:
        metadoc = cdb.get('u1db/_replica_uid')
        replica_uid = get_att_content(cdb, 'u1db/_replica_uid', 'u1db_json')
    except ResourceNotFound:
        continue

    #---------------------------------------------------------------------
    # Step 1: Set replica uid.
    #---------------------------------------------------------------------
    sdb._set_replica_uid(replica_uid)

    #---------------------------------------------------------------------
    # Step 2: Obtain metadata.
    #---------------------------------------------------------------------

    # obtain the transaction log: [['<doc_id>', '<trans_id>'], ...]
    transaction_log = get_att_content(
        cdb, 'u1db/_transaction_log', 'u1db_json')
    new_transaction_log = []
    gen = 1
    for (doc_id, trans_id) in transaction_log:
        new_transaction_log.append((gen, doc_id, trans_id))
        gen += 1
    transaction_log = new_transaction_log

    # obtain the conflict log: {'<doc_id>': ['<rev>', '<content>'], ...}
    conflict_log = get_att_content(cdb, 'u1db/_conflicts', 'u1db_json')

    # obtain the sync log:
    # {'<replica_uid>': ['<gen>', '<transaction_id>'], ...}
    other_generations = get_att_content(
        cdb, 'u1db/_other_generations', 'u1db_json')

    #---------------------------------------------------------------------
    # Step 3: Iterate over all documents in database.
    #---------------------------------------------------------------------
    doc_len = len(cdb)
    logger.info("(%d, %d) Found %d documents." % (db_idx, db_len, doc_len))
    doc_idx = 0
    threads = []
    for doc_id in cdb:
        doc_idx = doc_idx + 1

        semaphore_pool.acquire()
        thread = DocWorkerThread(dbname, doc_id, db_idx, db_len,
                                 doc_idx, doc_len, transaction_log,
                                 conflict_log, semaphore_pool.release)
        thread.daemon = True
        thread.start()
        threads.append(thread)

    map(lambda thread: thread.join(), threads)

    #---------------------------------------------------------------------
    # Step 4: Move sync log.
    #---------------------------------------------------------------------

    # move sync log
    sync_doc = {
        '_id': 'u1db_sync_log',
        'syncs': []
    }

    for replica_uid in other_generations:
        gen, transaction_id = other_generations[replica_uid]
        sync_doc['syncs'].append([replica_uid, gen, transaction_id])
    cdb.save(sync_doc)

    #---------------------------------------------------------------------
    # Step 5: Delete old meta documents.
    #---------------------------------------------------------------------

    # remove unused docs
    for doc_id in ['_transaction_log', '_conflicts', '_other_generations',
            '_indexes', '_replica_uid']:
        for prefix in ['u1db/', 'u1db%2F']:
            try:
                doc = cdb['%s%s' % (prefix, doc_id)]
                logger.info(
                    "(%d/%d) Deleting %s/%s/%s." %
                    (db_idx, db_len, dbname, 'u1db', doc_id))
                cdb.delete(doc)
            except ResourceNotFound:
                pass
