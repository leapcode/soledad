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
import couchdb
import logging
import argparse
import random
import string
import binascii
import json


SOLEDAD_CONFIG_FILE = '/etc/leap/soledad-server.conf'
PREFIX = '/tmp/soledad_test'
LOG_FORMAT = '%(asctime)s %(levelname)s %(message)s'


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
def gen_body(size):
    if os.path.exists(
            os.path.join(PREFIX, 'body-%d.json' % size)):
        logger.debug('Loading body with %d MB...' % size)
        with open(os.path.join(PREFIX, 'body-%d.json' % size), 'r') as f:
            return json.loads(f.read())
    else:
        length = int(size * 1024 ** 2)
        hexdata = binascii.hexlify(os.urandom(length))[:length]
        body = {
            'couch_rev': None,
            'u1db_rev': '1',
            'content': hexdata,
            'trans_id': '1',
            'conflicts': None,
            'update_conflicts': False,
        }
        logger.debug('Generating body with %d MB...' % size)
        with open(os.path.join(PREFIX, 'body-%d.json' % size), 'w+') as f:
            f.write(json.dumps(body))
        return body


def delete_doc(db):
    doc = db.get('largedoc')
    db.delete(doc)


def upload(db, size):
    ddoc_path = ['_design', 'docs', '_update', 'put', 'largedoc']
    resource = db.resource(*ddoc_path)
    body = gen_body(size)
    try:
        logger.debug('Uploading %d MB body...' % size)
        response = resource.put_json(
            body=body,
            headers={'content-type': 'application/json'})
        # the document might have been updated in between, so we check for
        # the return message
        msg = response[2].read()
        if msg == 'ok':
            delete_doc(db)
            logger.debug('Success uploading %d MB doc.' % size)
            return True
        else:
            # should not happen
            logger.error('Unexpected error uploading %d MB doc: %s' % (size, msg))
            return False
    except Exception as e:
        logger.debug('Failed to upload %d MB doc: %s' % (size, str(e)))
        return False


def find_max_upload_size(dbname):
    couch_url = get_couch_url()
    db_url = '%s/%s' % (couch_url, dbname)
    logger.debug('Couch URL: %s' % db_url)
    # get a 'raw' couch handler
    server = couchdb.client.Server(couch_url)
    db = server[dbname]
    # delete eventual leftover from last run
    largedoc = db.get('largedoc')
    if largedoc is not None:
        db.delete(largedoc)
    # phase 1: increase upload size exponentially
    logger.info('Starting phase 1: increasing size exponentially.')
    size = 1
    while True:
        if upload(db, size):
            size *= 2
        else:
            break
    # phase 2: binary search for maximum value
    unable = size
    able = size / 2
    logger.info('Starting phase 2: binary search for maximum value.')
    while unable - able > 1:
        size = able + ((unable - able) / 2)
        if upload(db, size):
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
        'dbname', help='the name of the database to test in')
    args = parser.parse_args()

    # log to file
    if args.logfile is not None:
        add_file_handler(args.logfile)

    # set loglevel
    if args.debug is True:
        config_log(logging.DEBUG)
    else:
        config_log(logging.INFO)

    # run test and report
    logger.info('Will test using db %s.' % args.dbname)
    maxsize = find_max_upload_size(args.dbname)
    logger.info('Max upload size is %d MB.' % maxsize)
