#!/usr/bin/python

# scenarios:
#   1. soledad instantiation time.
#     a. for unexisting db.
#     b. for existing db.
#   2. soledad doc storage/retrieval.
#     a. 1 KB document.
#     b  10 KB.
#     c. 100 KB.
#     d. 1 MB.


import logging
import getpass
import tempfile
import argparse
import shutil
import timeit


from util import ValidateUserHandle

# benchmarking args
REPEAT_NUMBER = 1000
DOC_SIZE = 1024


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
        '-l', dest='logfile', required=False, default='/tmp/benchhmark-storage.log',
        help='the file to which write the benchmark logs')
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

    return args.username, args.provider, passphrase, basedir, args.logfile


if __name__ == '__main__':
    username, provider, passphrase, basedir, logfile = parse_args()
    create_results = []
    getall_results = []
    for i in [1, 200, 400, 600, 800, 1000]:
        tempdir = tempfile.mkdtemp(dir=basedir)
        setup_common = """
import os
#from benchmark_storage_utils import benchmark_fun
#from benchmark_storage_utils import get_soledad_instance
from client_side_db import get_soledad_instance
sol = get_soledad_instance('%s', '%s', '%s', '%s')
        """ % (username, provider, passphrase, tempdir)

        setup_create = setup_common + """
content = {'data': os.urandom(%d/2).encode('hex')}
""" % (DOC_SIZE * i)
        time = timeit.timeit(
            'sol.create_doc(content);',
            setup=setup_create, number=REPEAT_NUMBER)
        create_results.append((DOC_SIZE*i, time))
        print "CREATE: %d %f" % (DOC_SIZE*i, time)

        setup_get = setup_common + """
doc_ids = [doc.doc_id for doc in sol.get_all_docs()[1]]
"""

        time = timeit.timeit(
            "[sol.get_doc(doc_id) for doc_id in doc_ids]",
            setup=setup_get, number=1)
        getall_results.append((DOC_SIZE*i, time))
        print "GET_ALL: %d %f" % (DOC_SIZE*i, time)
        shutil.rmtree(tempdir)
    print "# size, time for creation of %d docs" % REPEAT_NUMBER
    for size, time in create_results:
        print size, time
    print "# size, time for retrieval of %d docs" % REPEAT_NUMBER
    for size, time in getall_results:
        print size, time
    shutil.rmtree(basedir)

