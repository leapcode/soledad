#!/usr/bin/python


import argparse
import logging


from util import StatsLogger, ValidateUserHandle
from client_side_db import get_soledad_instance
#from plot import plot


# create a logger
logger = logging.getLogger(__name__)
LOG_FORMAT = '%(asctime)s %(message)s'
logging.basicConfig(format=LOG_FORMAT, level=logging.INFO)


# main program

if __name__ == '__main__':

    # parse command line
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'user@provider', action=ValidateUserHandle, help='the user handle')
    parser.add_argument(
        '-b', dest='basedir', required=False, default=None,
        help='soledad base directory')
    parser.add_argument(
        '-p', dest='passphrase', required=False, default=None,
        help='the user passphrase')
    parser.add_argument(
        '-l', dest='logfile', required=False, default='/tmp/profile.log',
        help='the file to which write the log')
    args = parser.parse_args()

    # get the password
    passphrase = args.passphrase
    if passphrase is None:
        passphrase = getpass.getpass(
            'Password for %s@%s: ' % (args.username, args.provider))

    # get the basedir
    basedir = args.basedir
    if basedir is None:
        basedir = tempfile.mkdtemp()
    logger.info('Using %s as base directory.' % basedir)

    # get the soledad instance
    s = get_soledad_instance(
        args.username, args.provider, passphrase, basedir)
    for i in xrange(10):
        s.create_doc({})

    sl = StatsLogger(
        "soledad-sync", args.logfile, procs=["python"], interval=0.001)
    sl.start()
    s.sync()
    sl.stop()

    #plot(args.logfile)
