#!/usr/bin/python

# The purpose of this script is to stress a soledad server by:
#
#   - Instantiating multiple clients.
#   - Creating many documents in each client.
#   - Syncing all at the same time with th server multiple times, until
#     they've all reached an agreement on the state of the databases and
#     there's nothing else to be synced.


import threading
import tempfile
import argparse
import logging
import re
import getpass
import time
import shutil


from client_side_db import get_soledad_instance


from leap.soledad.client import BootstrapSequenceError


NUMBER_OF_REPLICAS = 1
DOCUMENTS_PER_REPLICA = 10


# create a logger
logger = logging.getLogger(__name__)
LOG_FORMAT = '%(asctime)s %(message)s'
logging.basicConfig(format=LOG_FORMAT, level=logging.INFO)


class WorkerThread(threading.Thread):

    def __init__(self, thread_id, soledad, all_set):
        threading.Thread.__init__(self)
        self._id = thread_id
        self._soledad = soledad
        self._all_set = all_set
        self._done_creating = threading.Event()

    def run(self):
        # create many documents
        logger.info('[replica %d] creating documents...' % self._id)
        for i in xrange(DOCUMENTS_PER_REPLICA):
            self._soledad.create_doc({'a_doc': i})
        # wait for others
        self._done_creating.set()
        logger.info('[replica %d] done creating documents.' % self._id)
        self._all_set.wait()
        # sync
        successes = 0
        while True:
            logger.info('[replica %d] syncing.' % self._id)
            if self._id == 1:
                time.sleep(5)
            old_gen = self._soledad.sync()
            logger.info('[replica %d] synced.' % self._id)
            new_gen = self._soledad._db._get_generation()
            logger.info('[replica %d] old gen %d - new gen %d.' %
                (self._id, old_gen, new_gen))
            if old_gen == new_gen:
                successes += 1
                logger.info('[replica %d] sync not needed.' % self._id)
                if successes == 3:
                    break


def stress_test(username, provider, passphrase, basedir):
    threads = []
    all_set = threading.Event()
    for i in xrange(NUMBER_OF_REPLICAS):
        logging.info('[main] starting thread %d.' % i)
        s = get_soledad_instance(
            username,
            provider,
            passphrase,
            tempfile.mkdtemp(dir=basedir))
        t = WorkerThread(i, s, all_set)
        t.start()
        threads.append(t)
    map(lambda t: t._done_creating.wait(), threads)
    all_set.set()
    map(lambda t: t.join(), threads)
    logger.info('Removing dir %s' % basedir)
    shutil.rmtree(basedir)


# main program

if __name__ == '__main__':

    class ValidateUserHandle(argparse.Action):
        def __call__(self, parser, namespace, values, option_string=None):
            m = re.compile('^([^@]+)@([^@]+\.[^@]+)$')
            res = m.match(values)
            if res == None:
                parser.error('User handle should have the form user@provider.')
            setattr(namespace, 'username', res.groups()[0])
            setattr(namespace, 'provider', res.groups()[1])

    # parse command line
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'user@provider', action=ValidateUserHandle, help='the user handle')
    parser.add_argument(
        '-b', dest='basedir', required=False, default=None, help='the user handle')
    args = parser.parse_args()

    # get the password
    passphrase = getpass.getpass(
        'Password for %s@%s: ' % (args.username, args.provider))

    # get the basedir
    basedir = args.basedir
    if basedir is None:
        basedir = tempfile.mkdtemp()
    logger.info('[main] using %s as base directory.' % basedir)

    stress_test(args.username, args.provider, passphrase, basedir)
