#!/usr/bin/env python

import shutil
import os
from argparse import ArgumentParser
from twisted.logger import Logger
from test_controller.utils import mkdir_p, payload

logger = Logger()


def _create_blob(path, data):
    with open(path, 'w') as f:
        logger.info('Creating %s' % path)
        f.write(data)


def create_blobs(target_dir, amount, size):
    delete_blobs(target_dir)
    data = payload(size * 1000)
    for i in xrange(amount):
        istr = str(i)
        blob_dir = '%s/%s/%s' % (istr[0], istr[0:3], istr[0:6])
        basedir = os.path.join(target_dir, '0/default/%s' % blob_dir)
        mkdir_p(basedir)
        _create_blob(os.path.join(basedir, str(i)), data)


def delete_blobs(target_dir):
    if not os.path.isdir(target_dir):
        return
    for f in os.listdir(target_dir):
        if f.isdigit():
            directory = os.path.join(target_dir, f)
            logger.info('Deleting %s' % directory)
            shutil.rmtree(directory)


def parse_args():
    parser = ArgumentParser()
    parser.add_argument(
        'target_dir',
        help='The target directory where templates will be written to.')
    parser.add_argument(
        '--amount', default=1000, type=int,
        help='The amount of users to create blobs to.')
    parser.add_argument(
        '--size', default=1000, type=int,
        help='The size of each template in KB.')
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    create_blobs(args.target_dir, args.amount, args.size * 1000)
