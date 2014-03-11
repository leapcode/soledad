#!/usr/bin/python

# This script finds the maximum upload size for a document in the current
# server. It pulls couch URL from Soledad config file and attempts multiple
# PUTs until it finds the maximum size supported by the server.
#
# As the Soledad couch user is not an admin, you have to pass a database into
# which the test will be run. The database should already exist and be
# initialized with soledad design documents.
#
# Use it like this:
#
#     ./find_max_upload_size.py <dbname>
#     ./find_max_upload_size.py -h

import os
import configparser
import logging
import argparse
import random
import string
import binascii
import json
import time
import uuid


from couchdb.client import Database
from socket import error as socket_error
from leap.soledad.common.couch import CouchDatabase


SOLEDAD_CONFIG_FILE = '/etc/leap/soledad-server.conf'
PREFIX = '/tmp/soledad_test'
LOG_FORMAT = '%(asctime)s %(levelname)s %(message)s'
RETRIES = 3  # number of times to retry uploading a document of a certain
             # size after a failure


# configure logger
logger = logging.getLogger(__name__)


def config_log(level):
    logging.basicConfig(format=LOG_FORMAT, level=level)


def log_to_file(filename):
    handler = logging.FileHandler(filename, mode='a')
    handler.setFormatter(logging.Formatter(fmt=LOG_FORMAT))
    logger.addHandler(handler)


# create test dir
if not os.path.exists(PREFIX):
    os.mkdir(PREFIX)


def get_couch_url(config_file=SOLEDAD_CONFIG_FILE):
    config = configparser.ConfigParser()
    config.read(config_file)
    return config['soledad-server']['couch_url']


# generate or load an uploadable doc with the given size in mb
def get_content(size):
    fname = os.path.join(PREFIX, 'content-%d.json' % size)
    if os.path.exists(fname):
        logger.debug('Loading content with %d MB...' % size)
        with open(fname, 'r') as f:
            return f.read()
    else:
        length = int(size * 1024 ** 2)
        logger.debug('Generating body with %d MB...' % size)
        content = binascii.hexlify(os.urandom(length))[:length]
        with open(fname, 'w') as f:
            f.write(content)
        return content


def delete_doc(db):
    doc = db.get('largedoc')
    db.delete(doc)


def upload(db, size, couch_db):
    # try many times to be sure that size is infeasible
    for i in range(RETRIES):
        # wait until server is up to upload
        while True:
            try:
                'largedoc' in couch_db
                break
            except socket_error:
                logger.debug('Waiting for server to come up...')
                time.sleep(1)
        # attempt to upload
        try:
            logger.debug(
                'Trying to upload %d MB document (attempt %d/%d)...' %
                (size, (i+1), RETRIES))
            content = get_content(size)
            logger.debug('Starting upload of %d bytes.' % len(content))
            doc = db.create_doc({'data': content}, doc_id='largedoc')
            delete_doc(couch_db)
            logger.debug('Success uploading %d MB doc.' % size)
            return True
        except Exception as e:
            logger.debug('Failed to upload %d MB doc: %s' % (size, str(e)))
    return False


def find_max_upload_size(db_uri):
    db = CouchDatabase.open_database(db_uri, False)
    couch_db = Database(db_uri)
    logger.debug('Database URI: %s' % db_uri)
    # delete eventual leftover from last run
    if 'largedoc' in couch_db:
        delete_doc(couch_db)
    # phase 1: increase upload size exponentially
    logger.info('Starting phase 1: increasing size exponentially.')
    size = 1
    #import ipdb; ipdb.set_trace()
    while True:
        if upload(db, size, couch_db):
            size *= 2
        else:
            break

    # phase 2: binary search for maximum value
    unable = size
    able = size / 2
    logger.info('Starting phase 2: binary search for maximum value.')
    while unable - able > 1:
        size = able + ((unable - able) / 2)
        if upload(db, size, couch_db):
            able = size
        else:
            unable = size
    return able


if __name__ == '__main__':
    # parse command line
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-d', action='store_true', dest='debug',
        help='print debugging information')
    parser.add_argument(
        '-l', dest='logfile',
        help='log output to file')
    parser.add_argument(
        'db_uri', help='the couch database URI to test')
    args = parser.parse_args()

    # log to file
    if args.logfile is not None:
        log_to_file(args.logfile)

    # set loglevel
    if args.debug is True:
        config_log(logging.DEBUG)
    else:
        config_log(logging.INFO)

    # run test and report
    logger.info('Will test using db at %s.' % args.db_uri)
    maxsize = find_max_upload_size(args.db_uri)
    logger.info('Max upload size is %d MB.' % maxsize)
