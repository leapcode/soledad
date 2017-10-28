#!/usr/bin/env python

import shutil
import os

from argparse import ArgumentParser

from test_controller.utils import mkdir_p, payload


def _create_blob(path, data):
    if not os.path.isfile(path):
        with open(path, 'w') as f:
            f.write(data)


def create_blobs(target_dir, amount, size):
    data = payload(size * 1000)
    for i in xrange(amount):
        basedir = os.path.join(target_dir, '%d/default/0/0/0' % i)
        mkdir_p(basedir)
        _create_blob(os.path.join(basedir, '0'), data)


def delete_blobs(target_dir):
    if not os.path.isdir(target_dir):
        return
    for f in os.listdir(target_dir):
        if f.isdigit():
            directory = os.path.join(target_dir, f)
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
