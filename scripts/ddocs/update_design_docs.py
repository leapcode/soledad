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

from urlparse import urlparse
from getpass import getpass
from ConfigParser import ConfigParser

from couchdb.client import Server
from couchdb.http import Resource
from couchdb.http import Session
from couchdb.http import ResourceNotFound

from leap.soledad.common import ddocs


MAX_THREADS = 20
DESIGN_DOCS = {
    '_design/docs': json.loads(binascii.a2b_base64(ddocs.docs)),
    '_design/syncs': json.loads(binascii.a2b_base64(ddocs.syncs)),
    '_design/transactions': json.loads(
        binascii.a2b_base64(ddocs.transactions)),
}


# create a logger
logger = logging.getLogger(__name__)
LOG_FORMAT = '%(asctime)s %(message)s'
logging.basicConfig(format=LOG_FORMAT, level=logging.INFO)


def _parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', dest='uuid', default=None, type=str,
                        help='the UUID of the user')
    parser.add_argument('-t', dest='threads', default=MAX_THREADS, type=int,
                        help='the number of parallel threads')
    return parser.parse_args()


def _get_url():
    # get couch url
    cp = ConfigParser()
    cp.read('/etc/soledad/soledad-server.conf')
    url = urlparse(cp.get('soledad-server', 'couch_url'))
    # get admin password
    netloc = re.sub('^.*@', '', url.netloc)
    url = url._replace(netloc=netloc)
    password = getpass("Admin password for %s: " % url.geturl())
    return url._replace(netloc='admin:%s@%s' % (password, netloc))


def _get_server(url):
    resource = Resource(
        url.geturl(), Session(retry_delays=[1, 2, 4, 8], timeout=10))
    return Server(url=resource)


def _confirm(url):
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

        logger.info(
            "(%d/%d) Updating db %s."
            % (self._db_idx, self._db_len, self._dbname))

        for doc_id in DESIGN_DOCS:
            try:
                doc = self._cdb[doc_id]
            except ResourceNotFound:
                doc = {'_id': doc_id}
            for key in ['lists', 'views', 'updates']:
                if key in DESIGN_DOCS[doc_id]:
                    doc[key] = DESIGN_DOCS[doc_id][key]
            self._cdb.save(doc)

        # release the semaphore
        self._release_fun()


def _launch_update_design_docs_thread(
        server, dbname, db_idx, db_len, semaphore_pool):
    semaphore_pool.acquire()  # wait for an available working slot
    thread = DBWorkerThread(
        server, dbname, db_idx, db_len, semaphore_pool.release)
    thread.daemon = True
    thread.start()
    return thread


def _update_design_docs(args, server):

    # find the actual databases to be updated
    dbs = []
    if args.uuid:
        dbs.append('user-%s' % args.uuid)
    else:
        for dbname in server:
            if dbname.startswith('user-') or dbname == 'shared':
                dbs.append(dbname)
            else:
                logger.info("Skipping db %s." % dbname)

    db_idx = 0
    db_len = len(dbs)
    semaphore_pool = threading.BoundedSemaphore(value=args.threads)
    threads = []

    # launch the update
    for db in dbs:
        db_idx += 1
        threads.append(
            _launch_update_design_docs_thread(
                server, db, db_idx, db_len, semaphore_pool))

    # wait for all threads to finish
    map(lambda thread: thread.join(), threads)


if __name__ == "__main__":
    args = _parse_args()
    url = _get_url()
    _confirm(url)
    server = _get_server(url)
    _update_design_docs(args, server)
