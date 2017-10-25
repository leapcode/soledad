# -*- coding: utf-8 -*-
# __main__.py
# Copyright (C) 2017 LEAP
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
import os
from leap.common.files import mkdir_p
from twisted.internet import defer
from . import BlobManager
from leap.soledad.client._document import BlobDoc
from twisted.logger import Logger

logger = Logger()


#
# testing facilities
#
@defer.inlineCallbacks
def testit(reactor):
    # configure logging to stdout
    from twisted.python import log
    import sys
    log.startLogging(sys.stdout)

    # parse command line arguments
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('--url', default='http://localhost:9000/')
    parser.add_argument('--path', default='/tmp/blobs')
    parser.add_argument('--secret', default='secret')
    parser.add_argument('--uuid', default='user')
    parser.add_argument('--token', default=None)
    parser.add_argument('--cert-file', default='')

    subparsers = parser.add_subparsers(help='sub-command help', dest='action')

    # parse upload command
    parser_upload = subparsers.add_parser(
        'upload', help='upload blob and bypass local db')
    parser_upload.add_argument('payload')
    parser_upload.add_argument('blob_id')

    # parse download command
    parser_download = subparsers.add_parser(
        'download', help='download blob and bypass local db')
    parser_download.add_argument('blob_id')
    parser_download.add_argument('--output-file', default='/tmp/incoming-file')

    # parse put command
    parser_put = subparsers.add_parser(
        'put', help='put blob in local db and upload')
    parser_put.add_argument('payload')
    parser_put.add_argument('blob_id')

    # parse get command
    parser_get = subparsers.add_parser(
        'get', help='get blob from local db, get if needed')
    parser_get.add_argument('blob_id')

    # parse delete command
    parser_get = subparsers.add_parser(
        'delete', help='delete blob from local and remote db')
    parser_get.add_argument('blob_id')

    # parse list command
    parser_get = subparsers.add_parser(
        'list', help='list local and remote blob ids')

    # parse send_missing command
    parser_get = subparsers.add_parser(
        'send_missing', help='send all pending upload blobs')

    # parse send_missing command
    parser_get = subparsers.add_parser(
        'fetch_missing', help='fetch all new server blobs')

    # parse arguments
    args = parser.parse_args()

    # TODO convert these into proper unittests

    def _manager():
        mkdir_p(os.path.dirname(args.path))
        manager = BlobManager(
            args.path, args.url,
            'A' * 32, args.secret,
            args.uuid, args.token, args.cert_file)
        return manager

    @defer.inlineCallbacks
    def _upload(blob_id, payload):
        logger.info(":: Starting upload only: %s" % str((blob_id, payload)))
        manager = _manager()
        with open(payload, 'r') as fd:
            yield manager._encrypt_and_upload(blob_id, fd)
        logger.info(":: Finished upload only: %s" % str((blob_id, payload)))

    @defer.inlineCallbacks
    def _download(blob_id):
        logger.info(":: Starting download only: %s" % blob_id)
        manager = _manager()
        result = yield manager._download_and_decrypt(blob_id)
        logger.info(":: Result of download: %s" % str(result))
        if result:
            fd, _ = result
            with open(args.output_file, 'w') as f:
                logger.info(":: Writing data to %s" % args.output_file)
                f.write(fd.read())
        logger.info(":: Finished download only: %s" % blob_id)

    @defer.inlineCallbacks
    def _put(blob_id, payload):
        logger.info(":: Starting full put: %s" % blob_id)
        manager = _manager()
        size = os.path.getsize(payload)
        with open(payload) as fd:
            doc = BlobDoc(fd, blob_id)
            result = yield manager.put(doc, size=size)
        logger.info(":: Result of put: %s" % str(result))
        logger.info(":: Finished full put: %s" % blob_id)

    @defer.inlineCallbacks
    def _get(blob_id):
        logger.info(":: Starting full get: %s" % blob_id)
        manager = _manager()
        fd = yield manager.get(blob_id)
        if fd:
            logger.info(":: Result of get: " + fd.getvalue())
        logger.info(":: Finished full get: %s" % blob_id)

    @defer.inlineCallbacks
    def _delete(blob_id):
        logger.info(":: Starting deletion of: %s" % blob_id)
        manager = _manager()
        yield manager.delete(blob_id)
        logger.info(":: Finished deletion of: %s" % blob_id)

    @defer.inlineCallbacks
    def _list():
        logger.info(":: Listing local blobs")
        manager = _manager()
        local_list = yield manager.local_list()
        logger.info(":: Local list: %s" % local_list)
        logger.info(":: Listing remote blobs")
        remote_list = yield manager.remote_list()
        logger.info(":: Remote list: %s" % remote_list)

    @defer.inlineCallbacks
    def _send_missing():
        logger.info(":: Sending local pending upload docs")
        manager = _manager()
        yield manager.send_missing()
        logger.info(":: Finished sending missing docs")

    @defer.inlineCallbacks
    def _fetch_missing():
        logger.info(":: Fetching remote new docs")
        manager = _manager()
        yield manager.fetch_missing()
        logger.info(":: Finished fetching new docs")

    if args.action == 'upload':
        yield _upload(args.blob_id, args.payload)
    elif args.action == 'download':
        yield _download(args.blob_id)
    elif args.action == 'put':
        yield _put(args.blob_id, args.payload)
    elif args.action == 'get':
        yield _get(args.blob_id)
    elif args.action == 'delete':
        yield _delete(args.blob_id)
    elif args.action == 'list':
        yield _list()
    elif args.action == 'send_missing':
        yield _send_missing()
    elif args.action == 'fetch_missing':
        yield _fetch_missing()


if __name__ == '__main__':
    from twisted.internet.task import react
    react(testit)
