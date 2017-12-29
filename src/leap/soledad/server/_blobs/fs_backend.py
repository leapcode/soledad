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


def isolated(path):
    """
    A decorator that isolates execution of the decorated method using a file
    system lock based on the given path. A symlink in ``{path}.lock`` will be
    used to make sure only one isolated method is executed at a time for that
    path.
    """

    def decorator(method):

        def new_method(*args, **kwargs):
            dirname, _ = os.path.split(path)
            mkdir_p(dirname)
            name = path + '.lock'
            # TODO: evaluate the need to replace this for a readers-writer lock
            lock = defer.DeferredFilesystemLock(name)

            def _release(result):
                lock.unlock()
                return result

            d = lock.deferUntilLocked()
            d.addCallback(lambda _: method(*args, **kwargs))
            d.addCallbacks(_release, _release)
            return d

        return new_method

    return decorator


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

    def read_blob(self, user, blob_id, consumer, namespace='', range=None):
        path = self._get_path(user, blob_id, namespace)
        if not os.path.isfile(path):
            return defer.fail(BlobNotFound((user, blob_id)))

        @isolated(path)
        @defer.inlineCallbacks
        def _read_blob():
            logger.info('reading blob: %s - %s@%s'
                        % (user, blob_id, namespace))
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

        return _read_blob()

    def get_flags(self, user, blob_id, namespace=''):
        path = self._get_path(user, blob_id, namespace)
        if not os.path.isfile(path):
            return defer.fail(BlobNotFound((user, blob_id)))
        if not os.path.isfile(path + '.flags'):
            return defer.succeed([])

        @isolated(path)
        def _get_flags():
            try:
                with open(path + '.flags', 'r') as flags_file:
                    flags = json.loads(flags_file.read())
                    return defer.succeed(flags)
            except Exception as e:
                return defer.fail(e)

        return _get_flags()

    def set_flags(self, user, blob_id, flags, namespace=''):
        path = self._get_path(user, blob_id, namespace)
        if not os.path.isfile(path):
            return defer.fail(BlobNotFound((user, blob_id)))

        @isolated(path)
        def _set_flags():
            try:
                for flag in flags:
                    if flag not in ACCEPTED_FLAGS:
                        raise InvalidFlag(flag)
                with open(path + '.flags', 'w') as flags_file:
                    raw_flags = json.dumps(flags)
                    flags_file.write(raw_flags)
                    return defer.succeed(None)
            except Exception as e:
                return defer.fail(e)

        return _set_flags()

    def write_blob(self, user, blob_id, producer, namespace=''):
        path = self._get_path(user, blob_id, namespace)
        if os.path.isfile(path):
            return defer.fail(BlobExists((user, blob_id)))

        @isolated(path)
        @defer.inlineCallbacks
        def _write_blob():
            try:
                # limit the number of concurrent writes to disk
                yield self.semaphore.acquire()

                try:
                    mkdir_p(os.path.split(path)[0])
                except OSError as e:
                    logger.warn(
                        "Got exception trying to create directory: %r" % e)
                used = yield self.get_total_storage(user)
                length = producer.length / 1024.0
                if used + length > self.quota:
                    raise QuotaExceeded
                logger.info('writing blob: %s - %s' % (user, blob_id))
                with open(path, 'wb') as blobfile:
                    yield producer.startProducing(blobfile)
                used += length
                yield self._update_usage(user, used)
            finally:
                self.semaphore.release()

        return _write_blob()

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
        path = self._get_path(user, blob_id, namespace)
        if not os.path.isfile(path):
            return defer.fail(BlobNotFound((user, blob_id)))

        @isolated(path)
        def _delete_blob():
            self.__touch(path + '.deleted')
            os.unlink(path)
            try:
                os.unlink(path + '.flags')
            except Exception:
                pass
            return defer.succeed(None)

        return _delete_blob()

    def get_blob_size(self, user, blob_id, namespace=''):
        path = self._get_path(user, blob_id, namespace)
        if not os.path.isfile(path):
            return defer.fail(BlobNotFound((user, blob_id)))

        @isolated(path)
        def _get_blob_size():
            size = os.stat(path).st_size
            try:
                return defer.succeed(size)
            except Exception as e:
                return defer.fail(e)

        return _get_blob_size()

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
        path = self._get_path(user, blob_id, namespace)
        if not os.path.isfile(path):
            return defer.fail(BlobNotFound((user, blob_id)))

        @isolated(path)
        def _get_tag():
            try:
                with open(path) as doc_file:
                    doc_file.seek(-16, 2)
                    tag = base64.urlsafe_b64encode(doc_file.read())
                    return defer.succeed(tag)
            except Exception as e:
                return defer.fail(e)

        return _get_tag()

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

    @defer.inlineCallbacks
    def exists(self, user, blob_id, namespace):
        path = self._get_path(user, blob_id, namespace)

        @isolated(path)
        @defer.inlineCallbacks
        def _exists():
            defer.returnValue(os.path.isfile(path))

        return _exists()

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
