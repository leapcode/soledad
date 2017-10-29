#!/usr/bin/env python

# Handle creation of user databases for scalability tests.

import argparse
import json
import os
import time
import treq

from hashlib import sha512
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


def _log(db, item, action, res):
    logger.info('%s %s %s' % (item, db, action))
    return res


def _req(method, *args, **kwargs):
    method = getattr(treq, method)
    auth = os.environ.get('HTTP_AUTH')
    if auth:
        kwargs.update({'auth': tuple(auth.split(':'))})
    return method(*args, **kwargs)


@defer.inlineCallbacks
def delete_dbs(couch_url, dbs):
    deferreds = []
    for db in dbs:
        d = semaphore.run(_req, 'delete', urljoin(couch_url, db))
        logfun = partial(_log, 'table', db, 'deleted')
        d.addCallback(logfun)
        deferreds.append(d)
    responses = yield defer.gatherResults(deferreds)
    codes = map(lambda r: r.code, responses)
    assert all(map(lambda c: c == 200 or c == 404, codes))


@defer.inlineCallbacks
def create_dbs(couch_url, dbs):
    deferreds = []
    for db in dbs:
        d = semaphore.run(_req, 'put', urljoin(couch_url, db))
        logfun = partial(_log, 'table', db, 'created')
        d.addCallback(logfun)
        deferreds.append(d)
    responses = yield defer.gatherResults(deferreds)
    codes = map(lambda r: r.code, responses)
    assert all(map(lambda c: c == 201, codes))


def _get_tokens_db_name():
    prefix = 'tokens_'
    expire = 30 * 24 * 3600
    db_name = prefix + str(int(time.time() / expire))
    return db_name


@defer.inlineCallbacks
def _create_token(res, url, user_id):
    data = {'user_id': user_id, 'type': 'Token'}
    if res.code == 200:
        current = yield res.json()
        data['_rev'] = current['_rev']
    res = yield _req('put', url, json.dumps(data))
    defer.returnValue(res)


def create_tokens(couch_url, create):
    deferreds = []
    tokens_db = _get_tokens_db_name()
    for i in xrange(create):
        user_id = str(i)
        token = sha512('%s-token' % user_id).hexdigest()
        url = '/'.join([couch_url, tokens_db, token])
        d = semaphore.run(_req, 'get', url)
        d.addCallback(_create_token, url, user_id)
        logfun = partial(_log, 'token', user_id, 'created')
        d.addCallback(logfun)
        deferreds.append(d)
    return defer.gatherResults(deferreds)


@defer.inlineCallbacks
def ensure_dbs(couch_url=COUCH_URL, create=CREATE):
    # dbs = get_db_names(create)
    # yield delete_dbs(couch_url, dbs)
    # yield create_dbs(couch_url, dbs)
    yield create_tokens(couch_url, create)


@defer.inlineCallbacks
def main(couch_url, create):
    yield ensure_dbs(couch_url=couch_url, create=create)
    reactor.stop()


if __name__ == '__main__':
    args = parse_args()
    d = main(args.couch_url, args.create)
    reactor.run()
