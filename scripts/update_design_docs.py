#!/usr/bin/python

# This script updates Soledad's design documents in the session database and
# all user databases with contents from the installed leap.soledad.common
# package.

import json
import logging
import argparse
import re
import threading
import binascii


from getpass import getpass
from ConfigParser import ConfigParser
from couchdb.client import Server
from couchdb.http import Resource, Session
from datetime import datetime
from urlparse import urlparse


from leap.soledad.common import ddocs


# parse command line for the log file name
logger_fname = "/tmp/update-design-docs_%s.log" % \
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
threads = []

# get couch url
cp = ConfigParser()
cp.read('/etc/leap/soledad-server.conf')
url = urlparse(cp.get('soledad-server', 'couch_url'))

# get admin password
netloc = re.sub('^.*@', '', url.netloc)
url = url._replace(netloc=netloc)
password = getpass("Admin password for %s: " % url.geturl())
url = url._replace(netloc='admin:%s@%s' % (password, netloc))

resource = Resource(url.geturl(), Session(retry_delays=[1,2,4,8], timeout=10))
server = Server(url=resource)

hidden_url = re.sub(
    'http://(.*):.*@',
    'http://\\1:xxxxx@',
    url.geturl())

print """
==========
ATTENTION!
==========

This script will modify Soledad's shared and user databases in:

  %s

This script does not make a backup of the couch db data, so make sure you
have a copy or you may loose data.
""" % hidden_url
confirm = raw_input("Proceed (type uppercase YES)? ")

if confirm != "YES":
    exit(1)

# convert design doc content

design_docs = {
    '_design/docs': json.loads(binascii.a2b_base64(ddocs.docs)),
    '_design/syncs': json.loads(binascii.a2b_base64(ddocs.syncs)),
    '_design/transactions': json.loads(binascii.a2b_base64(ddocs.transactions)),
}

#
# Thread
#

class DBWorkerThread(threading.Thread):

    def __init__(self, server, dbname, db_idx, db_len, release_fun):
        threading.Thread.__init__(self)
        self._dbname = dbname
        self._cdb = server[self._dbname]
        self._db_idx = db_idx
        self._db_len = db_len
        self._release_fun = release_fun

    def run(self):

        logger.info("(%d/%d) Updating db %s." % (self._db_idx, self._db_len,
                    self._dbname))

        for doc_id in design_docs:
            doc = self._cdb[doc_id]
            for key in ['lists', 'views', 'updates']:
                if key in design_docs[doc_id]:
                    doc[key] = design_docs[doc_id][key]
            self._cdb.save(doc)

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


    # get access to couch db
    cdb = Server(url.geturl())[dbname]

    #---------------------------------------------------------------------
    # Start DB worker thread
    #---------------------------------------------------------------------
    semaphore_pool.acquire()
    thread = DBWorkerThread(server, dbname, db_idx, db_len, semaphore_pool.release)
    thread.daemon = True
    thread.start()
    threads.append(thread)

map(lambda thread: thread.join(), threads)
