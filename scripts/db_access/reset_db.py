#!/usr/bin/python

# This script can be run on server side to completelly reset a user database.
#
# WARNING: running this script over a database will delete all documents but
# the one with id u1db_config (which contains db metadata) and design docs
# needed for couch backend.


import sys
from ConfigParser import ConfigParser
import threading
import logging
from couchdb import Database as CouchDatabase


if len(sys.argv) != 2:
    print 'Usage: %s <uuid>' % sys.argv[0]
    exit(1)

uuid = sys.argv[1]


# create a logger
logger = logging.getLogger(__name__)
LOG_FORMAT = '%(asctime)s %(message)s'
logging.basicConfig(format=LOG_FORMAT, level=logging.INFO)


# get couch url
cp = ConfigParser()
cp.read('/etc/leap/soledad-server.conf')
url = cp.get('soledad-server', 'couch_url')


# confirm
yes = raw_input("Are you sure you want to reset the database for user %s "
                "(type YES)? " % uuid)
if yes != 'YES':
    print 'Bailing out...'
    exit(2)


db = CouchDatabase('%s/user-%s' % (url, uuid))


class _DeleterThread(threading.Thread):

    def __init__(self, db, doc_id, release_fun):
        threading.Thread.__init__(self)
        self._db = db
        self._doc_id = doc_id
        self._release_fun = release_fun

    def run(self):
        logger.info('[%s] deleting doc...' % self._doc_id)
        del self._db[self._doc_id]
        logger.info('[%s] done.' % self._doc_id)
        self._release_fun()


semaphore_pool = threading.BoundedSemaphore(value=20)


threads = []
for doc_id in db:
    if doc_id != 'u1db_config' and not doc_id.startswith('_design'):
        semaphore_pool.acquire()
        logger.info('[main] launching thread for doc: %s' % doc_id)
        t = _DeleterThread(db, doc_id, semaphore_pool.release)
        t.start()
        threads.append(t)


logger.info('[main] waiting for threads.')
map(lambda thread: thread.join(), threads)


logger.info('[main] done.')
