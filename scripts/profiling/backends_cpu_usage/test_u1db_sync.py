#!/usr/bin/python


import tempfile
import logging
import shutil
import os
import time
import binascii

from leap.soledad.common import l2db
from leap.soledad.client.sqlcipher import open as sqlcipher_open

from log_cpu_usage import LogCpuUsage
from u1dblite import open as u1dblite_open
from u1dbcipher import open as u1dbcipher_open


DOCS_TO_SYNC = 1000
SMALLEST_DOC_SIZE = 1 * 1024  # 1 KB
BIGGEST_DOC_SIZE = 100 * 1024  # 100 KB


def get_data(size):
    return binascii.hexlify(os.urandom(size / 2))


def run_test(testname, open_fun, tempdir, docs, *args):
    logger.info('Starting test \"%s\".' % testname)

    # instantiate dbs
    db1 = open_fun(os.path.join(tempdir, testname + '1.db'), *args)
    db2 = open_fun(os.path.join(tempdir, testname + '2.db'), *args)

    # get sync target and synchsonizer
    target = db2.get_sync_target()
    synchronizer = l2db.sync.Synchronizer(db1, target)

    # generate lots of small documents
    logger.info('Creating %d documents in source db...' % DOCS_TO_SYNC)
    for content in docs:
        db1.create_doc(content)
    logger.info('%d documents created in source db.' % DOCS_TO_SYNC)

    # run the test
    filename = testname + '.txt'
    logger.info('Logging CPU usage to %s.' % filename)
    log_cpu = LogCpuUsage(filename)
    tstart = time.time()

    # start logging cpu
    log_cpu.start()
    logger.info('Sleeping for 5 seconds...')
    time.sleep(5)

    # sync
    logger.info('Starting sync...')
    sstart = time.time()
    synchronizer.sync()
    send = time.time()
    logger.info('Sync finished.')

    # stop logging cpu
    logger.info('Sleeping for 5 seconds...')
    time.sleep(5)
    tend = time.time()
    log_cpu.stop()

    # report
    logger.info('Total sync time: %f seconds' % (send - sstart))
    logger.info('Total test time: %f seconds' % (tend - tstart))
    logger.info('Finished test \"%s\".' % testname)

    # close dbs
    db1.close()
    db2.close()


if __name__ == '__main__':

    # configure logger
    logger = logging.getLogger(__name__)
    LOG_FORMAT = '%(asctime)s %(message)s'
    logging.basicConfig(format=LOG_FORMAT, level=logging.INFO)

    # get a temporary dir
    tempdir = tempfile.mkdtemp()
    logger.info('Using temporary directory %s' % tempdir)

    # create a lot of documents with random sizes
    docs = []
    for i in xrange(DOCS_TO_SYNC):
        docs.append({
            'index': i,
            # 'data': get_data(
            #    random.randrange(
            #        SMALLEST_DOC_SIZE, BIGGEST_DOC_SIZE))
        })

    # run tests
    run_test('sqlite', l2db.open, tempdir, docs, True)
    run_test('sqlcipher', sqlcipher_open, tempdir, docs, '123456', True)
    run_test('u1dblite', u1dblite_open, tempdir, docs)
    run_test('u1dbcipher', u1dbcipher_open, tempdir, docs, '123456', True)

    # remove temporary dir
    logger.info('Removing temporary directory %s' % tempdir)
    shutil.rmtree(tempdir)
