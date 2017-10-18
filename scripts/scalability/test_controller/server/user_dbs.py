#!/usr/bin/env python

# Handle creation of user databases for scalability tests.

import argparse
import treq

from functools import partial
from urlparse import urljoin

from twisted.internet import reactor, defer
from twisted.logger import Logger

COUCH_URL = "http://127.0.0.1:5984"
CREATE = 1000


logger = Logger()


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--couch-url', default=COUCH_URL,
                        help='The URL to the CouchDB server.')
    parser.add_argument('--create', default=CREATE,
                        help='The number of databases to create.')
    return parser.parse_args()


def get_db_names(create):
    dbs = []
    for i in xrange(create):
        dbname = 'user-%d' % i
        dbs.append(dbname)
    return dbs


semaphore = defer.DeferredSemaphore(20)


def _log(db, action, res):
    logger.info('table %s %s' % (db, action))
    return res


@defer.inlineCallbacks
def delete_dbs(dbs):
    deferreds = []
    for db in dbs:
        d = semaphore.run(treq.delete, urljoin(COUCH_URL, db))
        logfun = partial(_log, db, 'deleted')
        d.addCallback(logfun)
        deferreds.append(d)
    responses = yield defer.gatherResults(deferreds)
    codes = map(lambda r: r.code, responses)
    assert all(map(lambda c: c == 200 or c == 404, codes))


@defer.inlineCallbacks
def create_dbs(dbs):
    deferreds = []
    for db in dbs:
        d = semaphore.run(treq.put, urljoin(COUCH_URL, db))
        logfun = partial(_log, db, 'created')
        d.addCallback(logfun)
        deferreds.append(d)
    responses = yield defer.gatherResults(deferreds)
    codes = map(lambda r: r.code, responses)
    assert all(map(lambda c: c == 201, codes))


@defer.inlineCallbacks
def ensure_dbs(couch_url=COUCH_URL, create=CREATE):
    dbs = get_db_names(create)
    yield delete_dbs(dbs)
    yield create_dbs(dbs)


@defer.inlineCallbacks
def main(couch_url, create):
    yield ensure_dbs(couch_url, create)
    reactor.stop()


if __name__ == '__main__':
    args = parse_args()
    d = main(args.couch_url, args.create)
    reactor.run()
