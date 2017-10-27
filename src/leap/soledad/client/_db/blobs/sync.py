# -*- coding: utf-8 -*-
# _blobs.py
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
"""
Synchronization between blobs client/server
"""
from twisted.internet import defer
from twisted.internet import reactor
from twisted.logger import Logger
from twisted.internet import error
from .sql import SyncStatus
from .errors import RetriableTransferError
logger = Logger()


def sleep(seconds):
    d = defer.Deferred()
    reactor.callLater(seconds, d.callback, None)
    return d


MAX_WAIT = 60  # In seconds. Max time between retries


@defer.inlineCallbacks
def with_retry(func, *args, **kwargs):
    retry_wait = 1
    retriable_errors = (error.ConnectError, error.ConnectionClosed,
                        RetriableTransferError,)
    while True:
        try:
            yield func(*args, **kwargs)
            break
        except retriable_errors:
            yield sleep(retry_wait)
            retry_wait = min(retry_wait + 10, MAX_WAIT)


class BlobsSynchronizer(object):

    @defer.inlineCallbacks
    def refresh_sync_status_from_server(self, namespace=''):
        d1 = self.remote_list(namespace=namespace)
        d2 = self.local_list(namespace=namespace)
        remote_list, local_list = yield defer.gatherResults([d1, d2])
        pending_download_ids = tuple(set(remote_list) - set(local_list))
        yield self.local.update_batch_sync_status(
            pending_download_ids,
            SyncStatus.PENDING_DOWNLOAD,
            namespace=namespace)

    @defer.inlineCallbacks
    def send_missing(self, namespace=''):
        """
        Compare local and remote blobs and send what's missing in server.

        :param namespace:
            Optional parameter to restrict operation to a given namespace.
        :type namespace: str
        """
        missing = yield self.local.list_status(
            SyncStatus.PENDING_UPLOAD, namespace)
        total = len(missing)
        logger.info("Will send %d blobs to server." % total)
        deferreds = []
        semaphore = defer.DeferredSemaphore(self.concurrent_transfers_limit)

        for i in xrange(total):
            blob_id = missing.pop()
            d = semaphore.run(
                with_retry, self.__send_one, blob_id, namespace, i, total)
            deferreds.append(d)
        yield defer.gatherResults(deferreds, consumeErrors=True)

    @defer.inlineCallbacks
    def __send_one(self, blob_id, namespace, i, total):
        logger.info("Sending blob to server (%d/%d): %s"
                    % (i, total, blob_id))
        fd = yield self.local.get(blob_id, namespace=namespace)
        yield self._encrypt_and_upload(blob_id, fd)
        yield self.local.update_sync_status(blob_id, SyncStatus.SYNCED)

    @defer.inlineCallbacks
    def fetch_missing(self, namespace=''):
        """
        Compare local and remote blobs and fetch what's missing in local
        storage.

        :param namespace:
            Optional parameter to restrict operation to a given namespace.
        :type namespace: str
        """
        # TODO: Use something to prioritize user requests over general new docs
        d = self.local_list_status(SyncStatus.PENDING_DOWNLOAD, namespace)
        docs_we_want = yield d
        total = len(docs_we_want)
        logger.info("Will fetch %d blobs from server." % total)
        deferreds = []
        semaphore = defer.DeferredSemaphore(self.concurrent_transfers_limit)

        for i in xrange(len(docs_we_want)):
            blob_id = docs_we_want.pop()
            logger.info("Fetching blob (%d/%d): %s" % (i, total, blob_id))
            d = semaphore.run(with_retry, self.get, blob_id, namespace)
            deferreds.append(d)
        yield defer.gatherResults(deferreds, consumeErrors=True)

    @defer.inlineCallbacks
    def sync(self, namespace=''):
        try:
            yield self.refresh_sync_status_from_server(namespace)
            yield self.fetch_missing(namespace)
            yield self.send_missing(namespace)
        except defer.FirstError as e:
            e.subFailure.raiseException()
