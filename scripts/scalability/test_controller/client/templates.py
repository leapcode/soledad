#!/usr/bin/env python

import mock
import os

from argparse import ArgumentParser
from io import BytesIO
from tempfile import mkdtemp

from twisted.internet import reactor, defer

from leap.soledad.client._db.blobs import BlobManager

from test_controller.utils import mkdir_p, payload


DEFAULT_TARGET_DIR = './blob-templates'


def _get_put_function(path):
    def _put(_, data, params=None):
        with open(path, 'w') as f:
            f.write(data.read())
        return defer.succeed(mock.Mock(code=200))
    return _put


def _get_encrypt_function(user, path):
    tempdir = mkdtemp()
    manager = BlobManager(tempdir, None, '123', '123', user)
    manager._client.put = _get_put_function(path)
    return manager._encrypt_and_upload


def _encrypt(path, data):
    encrypt = _get_encrypt_function('user-0', path)
    return encrypt('blob', BytesIO(data))


def create_blob_templates(target_dir, amount, size):
    mkdir_p(target_dir)
    data = payload(size)
    semaphore = defer.DeferredSemaphore(20)
    deferreds = []
    for i in xrange(amount):
        path = os.path.join(target_dir,
                            '%dK-%d.blob' % (size / 1000, i))
        d = semaphore.run(_encrypt, path, data)
        deferreds.append(d)
    return defer.gatherResults(deferreds)


def parse_args():
    parser = ArgumentParser()
    parser.add_argument(
        'target_dir',
        help='The target directory where templates will be written to.')
    parser.add_argument(
        '--amount', default=1000, type=int,
        help='The number of blob templates to create.')
    parser.add_argument(
        '--size', default=1000, type=int,
        help='The size of each template in KB.')
    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    d = create_blob_templates(args.target_dir, args.amount, args.size * 1000)
    d.addCallback(lambda _: reactor.stop())
    reactor.run()
