# -*- coding: utf-8 -*-
# _blobs/fs_backend.py
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
A backend for blobs that stores in filesystem.
"""
import base64
import json
import os
import time

from collections import defaultdict
from zope.interface import implementer

from twisted.internet import defer
from twisted.internet import utils
from twisted.web.static import NoRangeStaticProducer
from twisted.web.static import SingleRangeStaticProducer

from leap.common.files import mkdir_p
from leap.soledad.common.blobs import ACCEPTED_FLAGS
from leap.soledad.common.blobs import InvalidFlag
from leap.soledad.common.log import getLogger
from leap.soledad.server import interfaces

from .errors import BlobExists
from .errors import BlobNotFound
from .errors import QuotaExceeded
from .util import VALID_STRINGS


logger = getLogger(__name__)


class NoRangeProducer(NoRangeStaticProducer):
    """
    A static file producer that fires a deferred when it's finished.
    """

    def start(self):
        NoRangeStaticProducer.start(self)
        if self.request is None:
            return defer.succeed(None)
        self.deferred = defer.Deferred()
        return self.deferred

    def stopProducing(self):
        NoRangeStaticProducer.stopProducing(self)
        if hasattr(self, 'deferred'):
            self.deferred.callback(None)


class SingleRangeProducer(SingleRangeStaticProducer):
    """
    A static file producer of a single file range that fires a deferred when
    it's finished.
    """

    def start(self):
        SingleRangeStaticProducer.start(self)
        if self.request is None:
            return defer.succeed(None)
        self.deferred = defer.Deferred()
        return self.deferred

    def stopProducing(self):
        SingleRangeStaticProducer.stopProducing(self)
        if hasattr(self, 'deferred'):
            self.deferred.callback(None)


@implementer(interfaces.IBlobsBackend)
class FilesystemBlobsBackend(object):

    USAGE_TIMEOUT = 30

    def __init__(self, blobs_path='/tmp/blobs/', quota=200 * 1024,
                 concurrent_writes=50):
        self.quota = quota
        self.semaphore = defer.DeferredSemaphore(concurrent_writes)
        if not os.path.isdir(blobs_path):
            os.makedirs(blobs_path)
        self.path = blobs_path
        self.usage = defaultdict(lambda: (None, None))
        self.usage_locks = defaultdict(defer.DeferredLock)

    def __touch(self, path):
        open(path, 'a')

    @defer.inlineCallbacks
    def read_blob(self, user, blob_id, consumer, namespace='', range=None):
        logger.info('reading blob: %s - %s@%s' % (user, blob_id, namespace))
        path = self._get_path(user, blob_id, namespace)
        logger.debug('blob path: %s' % path)
        with open(path) as fd:
            if range is None:
                producer = NoRangeProducer(consumer, fd)
            else:
                start, end = range
                offset = start
                size = end - start
                args = (consumer, fd, offset, size)
                producer = SingleRangeProducer(*args)
            yield producer.start()

    def get_flags(self, user, blob_id, namespace=''):
        try:
            path = self._get_path(user, blob_id, namespace)
        except Exception as e:
            return defer.fail(e)
        if not os.path.isfile(path):
            return defer.fail(BlobNotFound())
        if not os.path.isfile(path + '.flags'):
            return defer.succeed([])
        with open(path + '.flags', 'r') as flags_file:
            flags = json.loads(flags_file.read())
            return defer.succeed(flags)

    def set_flags(self, user, blob_id, flags, namespace=''):
        try:
            path = self._get_path(user, blob_id, namespace)
        except Exception as e:
            return defer.fail(e)
        if not os.path.isfile(path):
            return defer.fail(BlobNotFound())
        for flag in flags:
            if flag not in ACCEPTED_FLAGS:
                return defer.fail(InvalidFlag(flag))
        with open(path + '.flags', 'w') as flags_file:
            raw_flags = json.dumps(flags)
            flags_file.write(raw_flags)
        return defer.succeed(None)

    @defer.inlineCallbacks
    def write_blob(self, user, blob_id, producer, namespace=''):
        # limit the number of concurrent writes to disk
        yield self.semaphore.acquire()
        try:
            path = self._get_path(user, blob_id, namespace)
            try:
                mkdir_p(os.path.split(path)[0])
            except OSError as e:
                logger.warn("Got exception trying to create directory: %r" % e)
            if os.path.isfile(path):
                raise BlobExists
            used = yield self.get_total_storage(user)
            length = producer.length / 1024.0  # original length is in bytes
            if used + length > self.quota:
                raise QuotaExceeded
            logger.info('writing blob: %s - %s' % (user, blob_id))
            with open(path, 'wb') as blobfile:
                yield producer.startProducing(blobfile)
            used += length
            yield self._update_usage(user, used)
        finally:
            self.semaphore.release()

    @defer.inlineCallbacks
    def _update_usage(self, user, used):
        lock = self.usage_locks[user]
        yield lock.acquire()
        try:
            _, timestamp = self.usage[user]
            self.usage[user] = (used, timestamp)
        finally:
            lock.release()

    def delete_blob(self, user, blob_id, namespace=''):
        try:
            blob_path = self._get_path(user, blob_id, namespace)
        except Exception as e:
            return defer.fail(e)
        if not os.path.isfile(blob_path):
            return defer.fail(BlobNotFound())
        self.__touch(blob_path + '.deleted')
        os.unlink(blob_path)
        try:
            os.unlink(blob_path + '.flags')
        except Exception:
            pass
        return defer.succeed(None)

    def get_blob_size(self, user, blob_id, namespace=''):
        try:
            blob_path = self._get_path(user, blob_id, namespace)
        except Exception as e:
            return defer.fail(e)
        size = os.stat(blob_path).st_size
        return defer.succeed(size)

    def count(self, user, namespace=''):
        try:
            base_path = self._get_path(user, namespace=namespace)
        except Exception as e:
            return defer.fail(e)
        count = 0
        for _, _, filenames in os.walk(base_path):
            count += len(filter(lambda i: not i.endswith('.flags'), filenames))
        return defer.succeed(count)

    def list_blobs(self, user, namespace='', order_by=None, deleted=False,
                   filter_flag=False):
        namespace = namespace or 'default'
        blob_ids = []
        try:
            base_path = self._get_path(user, namespace=namespace)
        except Exception as e:
            return defer.fail(e)

        def match(name):
            if deleted:
                return name.endswith('.deleted')
            return VALID_STRINGS.match(name)
        for root, dirs, filenames in os.walk(base_path):
            blob_ids += [os.path.join(root, name) for name in filenames
                         if match(name)]
        if order_by in ['date', '+date']:
            blob_ids.sort(key=lambda x: os.path.getmtime(x))
        elif order_by == '-date':
            blob_ids.sort(key=lambda x: os.path.getmtime(x), reverse=True)
        elif order_by:
            exc = Exception("Unsupported order_by parameter: %s" % order_by)
            return defer.fail(exc)
        if filter_flag:
            blob_ids = list(self._filter_flag(blob_ids, filter_flag))
        blob_ids = [os.path.basename(path).replace('.deleted', '')
                    for path in blob_ids]
        return defer.succeed(blob_ids)

    def _filter_flag(self, blob_paths, flag):
        for blob_path in blob_paths:
            flag_path = blob_path + '.flags'
            if not os.path.isfile(flag_path):
                continue
            with open(flag_path, 'r') as flags_file:
                blob_flags = json.loads(flags_file.read())
            if flag in blob_flags:
                yield blob_path

    @defer.inlineCallbacks
    def get_total_storage(self, user):
        lock = self.usage_locks[user]
        yield lock.acquire()
        try:
            used, timestamp = self.usage[user]
            if used is None or time.time() > timestamp + self.USAGE_TIMEOUT:
                path = self._get_path(user)
                used = yield self._get_disk_usage(path)
                self.usage[user] = (used, time.time())
            defer.returnValue(used)
        finally:
            lock.release()

    def get_tag(self, user, blob_id, namespace=''):
        try:
            blob_path = self._get_path(user, blob_id, namespace)
        except Exception as e:
            return defer.fail(e)
        if not os.path.isfile(blob_path):
            return defer.fail(BlobNotFound())
        with open(blob_path) as doc_file:
            doc_file.seek(-16, 2)
            tag = base64.urlsafe_b64encode(doc_file.read())
            return defer.succeed(tag)

    @defer.inlineCallbacks
    def _get_disk_usage(self, start_path):
        if not os.path.isdir(start_path):
            defer.returnValue(0)
        cmd = ['/usr/bin/du', '-s', '-c', start_path]
        output = yield utils.getProcessOutput(cmd[0], cmd[1:])
        size = output.split()[0]
        defer.returnValue(int(size))

    def _validate_path(self, desired_path, user, blob_id):
        if not VALID_STRINGS.match(user):
            raise Exception("Invalid characters on user: %s" % user)
        if blob_id and not VALID_STRINGS.match(blob_id):
            raise Exception("Invalid characters on blob_id: %s" % blob_id)
        desired_path = os.path.realpath(desired_path)  # expand path references
        root = os.path.realpath(self.path)
        if not desired_path.startswith(root + os.sep + user):
            err = "User %s tried accessing a invalid path: %s" % (user,
                                                                  desired_path)
            raise Exception(err)
        return desired_path

    def exists(self, user, blob_id, namespace):
        try:
            path = self._get_path(user, blob_id=blob_id, namespace=namespace)
        except Exception as e:
            return defer.fail(e)
        return os.path.isfile(path)

    def _get_path(self, user, blob_id='', namespace=''):
        parts = [user]
        if blob_id:
            namespace = namespace or 'default'
            parts += self._get_path_parts(blob_id, namespace)
        elif namespace and not blob_id:
            parts += [namespace]  # namespace path
        else:
            pass  # root path
        path = os.path.join(self.path, *parts)
        return self._validate_path(path, user, blob_id)

    def _get_path_parts(self, blob_id, custom):
        if custom and not blob_id:
            return [custom]
        return [custom] + [blob_id[0], blob_id[0:3], blob_id[0:6]] + [blob_id]
