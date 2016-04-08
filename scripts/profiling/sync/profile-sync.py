#!/usr/bin/env python
"""
Example of usage:
    time ./profile-sync.py --no-stats --send-num 5 --payload-file sample \
    --repeat-payload -p password -b /tmp/foobarsync \
    test_soledad_sync_001@cdev.bitmask.net
"""

import argparse
import commands
import getpass
import logging
import mmap
import os
import tempfile

from datetime import datetime
from twisted.internet import reactor

from util import StatsLogger, ValidateUserHandle
from client_side_db import _get_soledad_instance, _get_soledad_info

from leap.common.events import flags
from leap.soledad.client.api import Soledad

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


def get_and_run_theseus_tracer():
    from theseus import Tracer
    t = Tracer()
    t.install()
    return t


def bail(msg):
    print "[!] %s" % msg


def create_docs(soledad, args):
    """
    Populates the soledad database with dummy messages, so we can exercise
    sending payloads during the sync.
    """
    sample_path = args.payload_f
    if not sample_path:
        bail('Need to pass a --payload-file')
        return
    if not os.path.isfile(sample_path):
        bail('--payload-file does not exist!')
        return

    numdocs = int(args.send_num)
    docsize = int(args.send_size)

    # XXX this will FAIL if the payload source is smaller to size * num
    # XXX could use a cycle iterator
    with open(sample_path, "r+b") as sample_f:
        fmap = mmap.mmap(sample_f.fileno(), 0, prot=mmap.PROT_READ)
        payload = fmap.read(docsize * 1024)
        for index in xrange(numdocs):
            if not args.repeat_payload:
                payload = fmap.read(docsize * 1024)
            s.create_doc({payload: payload})


def _get_soledad_instance_from_uuid(uuid, passphrase, basedir, server_url,
                                    cert_file, token):
    secrets_path = os.path.join(basedir, '%s.secret' % uuid)
    local_db_path = os.path.join(basedir, '%s.db' % uuid)
    return Soledad(
        uuid,
        unicode(passphrase),
        secrets_path=secrets_path,
        local_db_path=local_db_path,
        server_url=server_url,
        cert_file=cert_file,
        auth_token=token,
        defer_encryption=True,
        syncable=True)


# main program

if __name__ == '__main__':

    # parse command line
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'user@provider', action=ValidateUserHandle, help='the user handle')
    parser.add_argument(
        '-u', dest='uuid', required=False, default=None,
        help='uuid for local tests')
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
        '--no-send', dest='do_send', action='store_false',
        help='skip sending messages')
    parser.add_argument(
        '--send-size', dest='send_size', default=10,
        help='size of doc to send, in KB (default: 10)')
    parser.add_argument(
        '--send-num', dest='send_num', default=10,
        help='number of docs to send (default: 10)')
    parser.add_argument(
        '--repeat-payload', dest='repeat_payload', action='store_true',
        default=False)
    parser.add_argument(
        '--payload-file', dest="payload_f", default=None,
        help='path to a sample file to use for the payloads')

    parser.add_argument(
        '--no-stats', dest='do_stats', action='store_false',
        help='skip system stats')
    parser.add_argument(
        '--plot', dest='do_plot', action='store_true',
        help='do a graphical plot')
    parser.add_argument(
        '--plop', dest='do_plop', action='store_true',
        help='run sync script under plop profiler')
    parser.add_argument(
        '--theseus', dest='do_theseus', action='store_true',
        help='run sync script under theseus profiler')
    parser.set_defaults(
        do_send=True, do_stats=True, do_plot=False, do_plop=False,
        do_theseus=False,
    )
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

    if args.uuid:
        # We got an uuid. This is a local test, and we bypass
        # authentication and encryption.
        s = _get_soledad_instance_from_uuid(
            args.uuid, passphrase, basedir, 'http://localhost:2323', '', '')

    else:
        # Remote server. First, get remote info...
        uuid, server_url, cert_file, token = \
            _get_soledad_info(
                args.username, args.provider, passphrase, basedir)
        # ...and then get the soledad instance
        s = _get_soledad_instance(
            uuid, passphrase, basedir, server_url, cert_file, token)

    if args.do_send:
        create_docs(s, args)

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

        if args.do_theseus:
            theseus = get_and_run_theseus_tracer()
        else:
            theseus = None

        t0 = datetime.now()
        d = s.sync()
        d.addCallback(onSyncDone, sl, t0, plop_collector, theseus)

    def onSyncDone(sync_result, sl, t0, plop_collector, theseus):
        # TODO should write this to a result file
        print "GOT SYNC RESULT: ", sync_result
        t1 = datetime.now()
        if sl:
            sl.stop()
        if plop_collector:
            from plop.collector import PlopFormatter
            formatter = PlopFormatter()
            plop_collector.stop()
            if not os.path.isdir('profiles'):
                os.mkdir('profiles')
            with open('profiles/plop-sync-%s' % GITVER, 'w') as f:
                f.write(formatter.format(plop_collector))
        if theseus:
            with open('callgrind.theseus', 'wb') as outfile:
                theseus.write_data(outfile)
            theseus.uninstall()

        delta = (t1 - t0).total_seconds()
        # TODO should write this to a result file
        print "[+] Sync took %s seconds." % delta
        reactor.stop()

        if args.do_plot:
            from plot import plot
            plot(args.logfile)

    reactor.callWhenRunning(start_sync)
    reactor.run()
