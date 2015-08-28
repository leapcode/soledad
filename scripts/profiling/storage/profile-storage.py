#!/usr/bin/python

import os
import logging
import getpass
import tempfile
import argparse
import cProfile
import shutil
import pstats
import StringIO
import datetime


from client_side_db import get_soledad_instance
from util import ValidateUserHandle

# profiling args
NUM_DOCS = 1
DOC_SIZE = 1024**2


# create a logger
logger = logging.getLogger(__name__)
LOG_FORMAT = '%(asctime)s %(message)s'
logging.basicConfig(format=LOG_FORMAT, level=logging.INFO)


def parse_args():
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
        '-d', dest='logdir', required=False, default='/tmp/',
        help='the direcroty to which write the profile stats')
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

    return args.username, args.provider, passphrase, basedir, args.logdir

created_docs = []

def create_docs(sol, content):
    for i in xrange(NUM_DOCS):
        doc = sol.create_doc(content)
        created_docs.append(doc.doc_id)
        
def get_all_docs(sol):
    for doc_id in created_docs:
        sol.get_doc(doc_id)

def do_profile(logdir, sol):
    fname_prefix = os.path.join(
        logdir,
        "profile_%s" \
        % datetime.datetime.now().strftime('%Y-%m-%d_%H-%m-%S'))

    # profile create docs
    content = {'data': os.urandom(DOC_SIZE/2).encode('hex')}
    pr = cProfile.Profile()
    pr.runcall(
        create_docs,
        sol, content)
    s = StringIO.StringIO()
    ps = pstats.Stats(pr, stream=s).sort_stats('cumulative')
    ps.print_stats()
    ps.dump_stats("%s_creation.stats" % fname_prefix)
    print s.getvalue()

    # profile get all docs
    pr = cProfile.Profile()
    pr.runcall(
        get_all_docs,
        sol)
    s = StringIO.StringIO()
    ps = pstats.Stats(pr, stream=s).sort_stats('cumulative')
    ps.dump_stats("%s_retrieval.stats" % fname_prefix)
    ps.print_stats()
    print s.getvalue()


if __name__ == '__main__':
    username, provider, passphrase, basedir, logdir = parse_args()
    sol = get_soledad_instance(
        username,
        provider,
        passphrase,
        basedir)
    do_profile(logdir, sol)
    shutil.rmtree(basedir)

