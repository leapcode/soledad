#!/usr/bin/python

# This script can be run on server side to completelly reset a user database.
#
# WARNING: running this script over a database will delete all documents but
# the one with id u1db_config (which contains db metadata) and design docs
# needed for couch backend.
#
# Run it like this to get some help:
#
#     ./reset_db.py --help


import threading
import logging
import argparse
import re


from ConfigParser import ConfigParser
from couchdb import Database as CouchDatabase
from couchdb import Server as CouchServer


# create a logger
logger = logging.getLogger(__name__)
LOG_FORMAT = '%(asctime)s %(message)s'
logging.basicConfig(format=LOG_FORMAT, level=logging.INFO)


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


def get_confirmation(noconfirm, uuid, shared):
    msg = "Are you sure you want to reset %s (type YES)? "
    if shared:
        msg = msg % "the shared database"
    elif uuid:
        msg = msg % ("the database for user %s" % uuid)
    else:
        msg = msg % "all databases"
    if noconfirm is False:
        yes = raw_input(msg)
        if yes != 'YES':
            print 'Bailing out...'
            exit(2)


def get_url(empty):
    url = None
    if empty is False:
        # get couch url
        cp = ConfigParser()
        cp.read('/etc/soledad/soledad-server.conf')
        url = cp.get('soledad-server', 'couch_url')
    else:
        with open('/etc/couchdb/couchdb.netrc') as f:
            netrc = f.read()
            admin_password = re.match('^.* password (.*)$', netrc).groups()[0]
            url = 'http://admin:%s@127.0.0.1:5984' % admin_password
    return url


def reset_all_dbs(url, empty):
    server = CouchServer('%s' % (url))
    for dbname in server:
        if dbname.startswith('user-') or dbname == 'shared':
            reset_db(url, dbname, empty)


def reset_db(url, dbname, empty):
    db = CouchDatabase('%s/%s' % (url, dbname))
    semaphore_pool = threading.BoundedSemaphore(value=20)

    # launch threads for deleting docs
    threads = []
    for doc_id in db:
        if empty is False:
            if doc_id == 'u1db_config' or doc_id.startswith('_design'):
                continue
        semaphore_pool.acquire()
        logger.info('[main] launching thread for doc: %s' % doc_id)
        t = _DeleterThread(db, doc_id, semaphore_pool.release)
        t.start()
        threads.append(t)

    # wait for threads to finish
    logger.info('[main] waiting for threads.')
    map(lambda thread: thread.join(), threads)
    logger.info('[main] done.')


def _parse_args():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-u', dest='uuid', default=False,
        help='Reset database of given user.')
    group.add_argument('-s', dest='shared', action='store_true', default=False,
        help='Reset the shared database.')
    group.add_argument('-a', dest='all', action='store_true', default=False,
        help='Reset all user databases.')
    parser.add_argument(
        '-e', dest='empty', action='store_true', required=False, default=False,
        help='Empty database (do not preserve minimal set of u1db documents).')
    parser.add_argument(
        '-y', dest='noconfirm', action='store_true', required=False,
        default=False,
        help='Do not ask for confirmation.')
    return parser.parse_args(), parser


if __name__ == '__main__':
    args, parser = _parse_args()
    if not (args.uuid or args.shared or args.all):
        parser.print_help()
        exit(1)

    url = get_url(args.empty)
    get_confirmation(args.noconfirm, args.uuid, args.shared)
    if args.uuid:
        reset_db(url, "user-%s" % args.uuid, args.empty)
    elif args.shared:
        reset_db(url, "shared", args.empty)
    elif args.all:
        reset_all_dbs(url, args.empty)
