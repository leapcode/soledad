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
import netrc
import os

from argparse import ArgumentParser

from leap.soledad.server import load_configuration

from migrate_couch_schema import migrate


TARGET_VERSION = '0.8.2'
DEFAULT_COUCH_URL = 'http://127.0.0.1:5984'
CONF = load_configuration('/etc/soledad/soledad-server.conf')
NETRC_PATH = CONF['soledad-server']['admin_netrc']


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


def _default_couch_url():
    if not os.path.exists(NETRC_PATH):
        return DEFAULT_COUCH_URL
    parsed_netrc = netrc.netrc(NETRC_PATH)
    host, (login, _, password) = parsed_netrc.hosts.items()[0]
    url = ('http://%(login)s:%(password)s@%(host)s:5984' % {
           'login': login,
           'password': password,
           'host': host})
    return url


def _parse_args():
    parser = ArgumentParser()
    parser.add_argument(
        '--couch_url',
        help='the url for the couch database',
        default=_default_couch_url())
    parser.add_argument(
        '--do-migrate',
        help='actually perform the migration (otherwise '
             'just print what would be done)',
        action='store_true')
    parser.add_argument(
        '--log-file',
        help='the log file to use')
    parser.add_argument(
        '--pdb', action='store_true',
        help='escape to pdb shell in case of exception')
    return parser.parse_args()


def _enable_pdb():
    import sys
    from IPython.core import ultratb
    sys.excepthook = ultratb.FormattedTB(
        mode='Verbose', color_scheme='Linux', call_pdb=1)


if __name__ == '__main__':
    args = _parse_args()
    if args.pdb:
        _enable_pdb()
    _configure_logger(args.log_file)
    logger = logging.getLogger(__name__)
    try:
        migrate(args, TARGET_VERSION)
    except:
        logger.exception('Fatal error on migrate script!')
        raise
