#!/usr/bin/python


import logging
import argparse
import psutil
import time


def find_procs(procs):
    result = []
    for name, executable in procs:
        found = filter(
            lambda p: executable == p.name,
            psutil.process_iter())
        if len(found) == 1:
            result.append(found[0])
    return result


def log_memory(soledad, bigcouch):
    while True:
        print "%f %f" % \
            (soledad.get_memory_percent(), bigcouch.get_memory_percent())
        time.sleep(1)


if __name__ == '__main__':
    
    # configure logger
    logger = logging.getLogger(__name__)
    LOG_FORMAT = '%(asctime)s %(message)s'
    logging.basicConfig(format=LOG_FORMAT, level=logging.INFO)


    # parse command line
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-l', dest='logfile',
        help='log output to file')
    args = parser.parse_args()

    log_memory(*find_procs([
        ('Soledad', 'twistd'),
        ('Bigcouch', 'beam.smp')]))
    
