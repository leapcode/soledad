#!/usr/bin/env python

import argparse
import commands
import getpass
import logging
import tempfile

from datetime import datetime
from twisted.internet import reactor

from util import StatsLogger, ValidateUserHandle
from client_side_db import _get_soledad_instance, _get_soledad_info
from leap.common.events import flags

flags.set_events_enabled(False)


# create a logger
logger = logging.getLogger(__name__)
LOG_FORMAT = '%(asctime)s %(message)s'
logging.basicConfig(format=LOG_FORMAT, level=logging.INFO)

GITVER = commands.getoutput('git describe')


def get_and_run_plop_collector():
    from plop.collector import Collector
    collector = Collector()
    collector.start()
    return collector


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
    parser.add_argument(
        '--no-stats', dest='do_stats', action='store_false',
        help='skip system stats')
    parser.add_argument(
        '--plot', dest='do_plot', action='store_true',
        help='do a graphical plot')
    parser.add_argument(
        '--plop', dest='do_plop', action='store_true',
        help='run sync script under plop profiler')
    parser.set_defaults(do_stats=True, do_plot=False, do_plop=False)
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

    uuid, server_url, cert_file, token = \
        _get_soledad_info(
            args.username, args.provider, passphrase, basedir)
    # get the soledad instance
    s = _get_soledad_instance(
        uuid, passphrase, basedir, server_url, cert_file, token)

    for i in xrange(10):
        # XXX Profile this with more realistic payloads
        s.create_doc({})

    def start_sync():
        if args.do_stats:
            sl = StatsLogger(
                "soledad-sync", args.logfile, procs=["python"], interval=0.001)
            sl.start()
        else:
            sl = None

        if args.do_plop:
            plop_collector = get_and_run_plop_collector()
        else:
            plop_collector = None

        t0 = datetime.now()
        d = s.sync()
        d.addCallback(onSyncDone, sl, t0, plop_collector)

    def onSyncDone(sync_result, sl, t0, plop_collector):
        print "GOT SYNC RESULT: ", sync_result
        t1 = datetime.now()
        if sl:
            sl.stop()
        if plop_collector:
            from plop.collector import PlopFormatter
            formatter = PlopFormatter()
            plop_collector.stop()
            # XXX mkdir profiles dir if not exist
            with open('profiles/plop-sync-%s' % GITVER, 'w') as f:
                f.write(formatter.format(plop_collector))

        delta = (t1 - t0).total_seconds()
        print "[+] Sync took %s seconds." % delta
        reactor.stop()

        if args.do_plot:
            from plot import plot
            plot(args.logfile)

    reactor.callWhenRunning(start_sync)
    reactor.run()
