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


def log_usage(procs, logger):
    names = [proc.name for proc in procs]
    logger.info("Logging cpu and memory for: %s" % names)
    while True:
        s = '%f %f' %\
            (psutil.cpu_percent(), psutil.phymem_usage().percent)
        for proc in procs:
            s += ' %f %f' % \
                 (proc.get_cpu_percent(), proc.get_memory_percent())
        logger.info(s)
        time.sleep(1)


if __name__ == '__main__':
    # parse command line
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-l', dest='logfile',
        help='log output to file')
    args = parser.parse_args()

    # configure logger
    logger = logging.getLogger(__name__)
    LOG_FORMAT = '%(asctime)s %(message)s'
    logging.basicConfig(format=LOG_FORMAT, level=logging.INFO)

    if args.logfile is not None:
        handler = logging.FileHandler(args.logfile, mode='a')
        handler.setFormatter(logging.Formatter(fmt=LOG_FORMAT))
        logger.addHandler(handler)

    log_usage(find_procs([
        ('Soledad', 'twistd'),
        ('Bigcouch', 'beam.smp')]), logger)
