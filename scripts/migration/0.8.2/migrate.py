#!/usr/bin/env python
# migrate.py

"""
Migrate CouchDB schema to Soledad 0.8.2 schema.

******************************************************************************
                               ATTENTION!

  - This script does not backup your data for you. Make sure you have a backup
    copy of your databases before running this script!

  - Make sure you turn off any service that might be writing to the couch
    database before running this script.

******************************************************************************

Run this script with the --help option to see command line options.

See the README.md file for more information.
"""

import datetime
import logging
import os

from argparse import ArgumentParser

from migrate_couch_schema import migrate


TARGET_VERSION = '0.8.2'
DEFAULT_COUCH_URL = 'http://127.0.0.1:5984'


#
# command line args and execution
#

def _configure_logger(log_file):
    if not log_file:
        fname, _ = os.path.basename(__file__).split('.')
        timestr = datetime.datetime.now().strftime('%Y-%m-%d_%H:%M:%S')
        filename = 'soledad_%s_%s_%s.log' \
                   % (TARGET_VERSION, fname, timestr)
        dirname = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), 'log')
        log_file = os.path.join(dirname, filename)
    logging.basicConfig(
        filename=log_file,
        filemode='a',
        format='%(asctime)s,%(msecs)d %(levelname)s %(message)s',
        datefmt='%H:%M:%S',
        level=logging.DEBUG)


def _parse_args():
    parser = ArgumentParser()
    parser.add_argument(
        '--couch_url',
        help='the url for the couch database',
        default=DEFAULT_COUCH_URL)
    parser.add_argument(
        '--do-migrate',
        help='actually perform the migration (otherwise '
             'just print what would be done)',
        action='store_true')
    parser.add_argument(
        '--log-file',
        help='the log file to use')
    return parser.parse_args()


if __name__ == '__main__':
    args = _parse_args()
    _configure_logger(args.log_file)
    migrate(args, TARGET_VERSION)
