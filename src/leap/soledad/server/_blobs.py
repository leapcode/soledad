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
Blobs Server implementation.

This is a very simplistic implementation for the time being.
Clients should be able to opt-in util the feature is complete.

A more performant BlobsBackend can (and should) be implemented for production
environments.
"""
import os
import base64
import json
import re

from twisted.web import static
from twisted.web import resource
from twisted.web.client import FileBodyProducer
from twisted.web.server import NOT_DONE_YET
from twisted.internet import utils, defer

from zope.interface import implementer

from leap.common.files import mkdir_p
from leap.soledad.common.log import getLogger
from leap.soledad.server import interfaces
from leap.soledad.common.blobs import ACCEPTED_FLAGS
from leap.soledad.common.blobs import InvalidFlag


__all__ = ['BlobsResource']


logger = getLogger(__name__)

# Used for sanitizers, we accept only letters, numbers, '-' and '_'
VALID_STRINGS = re.compile('^[a-zA-Z0-9_-]+$')


# for the future:
# [ ] isolate user avatar in a safer way
# [ ] catch timeout in the server (and delete incomplete upload)
# [ ] chunking (should we do it on the client or on the server?)


class BlobNotFound(Exception):
    """
    Raised when a blob is not found in data storage backend.
    """


class BlobExists(Exception):
    """
    Raised when a blob already exists in data storage backend.
    """


class QuotaExceeded(Exception):
    """
    Raised when the quota would be exceeded if an operation would be held.
    """


@implementer(interfaces.IBlobsBackend)
class FilesystemBlobsBackend(object):

    def __init__(self, blobs_path='/tmp/blobs/', quota=200 * 1024,
                 concurrent_writes=50):
        self.quota = quota
        self.semaphore = defer.DeferredSemaphore(concurrent_writes)
        if not os.path.isdir(blobs_path):
            os.makedirs(blobs_path)
        self.path = blobs_path

    def __touch(self, path):
        open(path, 'a')

    def read_blob(self, user, blob_id, namespace=''):
        logger.info('reading blob: %s - %s@%s' % (user, blob_id, namespace))
        path = self._get_path(user, blob_id, namespace)
        logger.debug('blob path: %s' % path)
        res = static.File(path, defaultType='application/octet-stream')
        return res

    def get_flags(self, user, blob_id, namespace=''):
        path = self._get_path(user, blob_id, namespace)
        if not os.path.isfile(path):
            raise BlobNotFound
        if not os.path.isfile(path + '.flags'):
            return []
        with open(path + '.flags', 'r') as flags_file:
            return json.loads(flags_file.read())

    def set_flags(self, user, blob_id, flags, namespace=''):
        path = self._get_path(user, blob_id, namespace)
        if not os.path.isfile(path):
            raise BlobNotFound
        for flag in flags:
            if flag not in ACCEPTED_FLAGS:
                raise InvalidFlag(flag)
        with open(path + '.flags', 'w') as flags_file:
            raw_flags = json.dumps(flags)
            flags_file.write(raw_flags)

    @defer.inlineCallbacks
    def write_blob(self, user, blob_id, fd, namespace=''):
        yield self.semaphore.acquire()
        path = self._get_path(user, blob_id, namespace)
        try:
            mkdir_p(os.path.split(path)[0])
        except OSError as e:
            logger.warn("Got exception trying to create directory: %r" % e)
        if os.path.isfile(path):
            raise BlobExists
        used = yield self.get_total_storage(user)
        if used > self.quota:
            raise QuotaExceeded
        logger.info('writing blob: %s - %s' % (user, blob_id))
        fbp = FileBodyProducer(fd)
        with open(path, 'wb') as blobfile:
            yield fbp.startProducing(blobfile)
        yield self.semaphore.release()

    def delete_blob(self, user, blob_id, namespace=''):
        blob_path = self._get_path(user, blob_id, namespace)
        if not os.path.isfile(blob_path):
            raise BlobNotFound
        self.__touch(blob_path + '.deleted')
        os.unlink(blob_path)
        try:
            os.unlink(blob_path + '.flags')
        except Exception:
            pass
        return defer.succeed(None)

    def get_blob_size(self, user, blob_id, namespace=''):
        blob_path = self._get_path(user, blob_id, namespace)
        size = os.stat(blob_path).st_size
        return defer.succeed(size)

    def count(self, user, namespace=''):
        base_path = self._get_path(user, namespace=namespace)
        count = 0
        for _, _, filenames in os.walk(base_path):
            count += len(filter(lambda i: not i.endswith('.flags'), filenames))
        return defer.succeed(count)

    def list_blobs(self, user, namespace='', order_by=None, deleted=False,
                   filter_flag=False):
        namespace = namespace or 'default'
        blob_ids = []
        base_path = self._get_path(user, namespace=namespace)

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
            raise Exception("Unsupported order_by parameter: %s" % order_by)
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

    def get_total_storage(self, user):
        return self._get_disk_usage(self._get_path(user))

    def get_tag(self, user, blob_id, namespace=''):
        blob_path = self._get_path(user, blob_id, namespace)
        if not os.path.isfile(blob_path):
            raise BlobNotFound
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
        return os.path.isfile(
            self._get_path(user, blob_id=blob_id, namespace=namespace))

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


class ImproperlyConfiguredException(Exception):
    pass


class BlobsResource(resource.Resource):

    isLeaf = True

    # Allowed backend classes are defined here
    handlers = {"filesystem": FilesystemBlobsBackend}

    def __init__(self, backend, blobs_path, **backend_kwargs):
        resource.Resource.__init__(self)
        self._blobs_path = blobs_path
        backend_kwargs.update({'blobs_path': blobs_path})
        if backend not in self.handlers:
            raise ImproperlyConfiguredException("No such backend: %s", backend)
        self._handler = self.handlers[backend](**backend_kwargs)
        assert interfaces.IBlobsBackend.providedBy(self._handler)

    # TODO double check credentials, we can have then
    # under request.

    def render_GET(self, request):
        logger.info("http get: %s" % request.path)
        user, blob_id, namespace = self._validate(request)
        if not blob_id and request.args.get('only_count', [False])[0]:
            d = self._handler.count(user, namespace)
            d.addCallback(lambda count: json.dumps({"count": count}))
            d.addCallback(lambda count: request.write(count))
            d.addCallback(lambda _: request.finish())
            return NOT_DONE_YET
        elif not blob_id:
            order = request.args.get('order_by', [None])[0]
            filter_flag = request.args.get('filter_flag', [False])[0]
            deleted = request.args.get('deleted', [False])[0]
            d = self._handler.list_blobs(user, namespace,
                                         order_by=order, deleted=deleted,
                                         filter_flag=filter_flag)
            d.addCallback(lambda blobs: json.dumps(blobs))
            d.addCallback(lambda blobs: request.write(blobs))
            d.addCallback(lambda _: request.finish())
            return NOT_DONE_YET
        only_flags = request.args.get('only_flags', [False])[0]
        try:
            if only_flags:
                flags = self._handler.get_flags(user, blob_id, namespace)
                return json.dumps(flags)
            tag = self._handler.get_tag(user, blob_id, namespace)
            request.responseHeaders.setRawHeaders('Tag', [tag])
        except BlobNotFound:
            # 404 - Not Found
            request.setResponseCode(404)
            return "Blob doesn't exists: %s" % blob_id
        res = self._handler.read_blob(user, blob_id, namespace=namespace)
        return res.render_GET(request)

    def render_DELETE(self, request):
        logger.info("http put: %s" % request.path)
        user, blob_id, namespace = self._validate(request)

        def catchBlobNotFound(failure):
            failure.trap(BlobNotFound)
            request.setResponseCode(404)
            return "Blob doesn't exists: %s" % blob_id

        d = self._handler.delete_blob(user, blob_id, namespace=namespace)
        d.addCallback(lambda _: request.finish())
        d.addErrback(catchBlobNotFound)
        return NOT_DONE_YET

    def render_PUT(self, request):
        logger.info("http put: %s" % request.path)
        user, blob_id, namespace = self._validate(request)

        def catchBlobExists(failure):
            failure.trap(BlobExists)
            request.setResponseCode(409)
            request.write("Blob already exists: %s" % blob_id)
            request.finish()

        def catchQuotaExceeded(failure):
            failure.trap(QuotaExceeded)
            logger.error("Error 507: Quota exceeded for user: %s" % user)
            request.setResponseCode(507)
            request.write('Quota Exceeded!')
            request.finish()

        fd = request.content
        d = self._handler.write_blob(user, blob_id, fd, namespace=namespace)
        d.addCallback(lambda _: request.finish())
        d.addErrback(catchBlobExists)
        d.addErrback(catchQuotaExceeded)
        d.addErrback(self._error, request)
        return NOT_DONE_YET

    def render_POST(self, request):
        logger.info("http post: %s" % request.path)
        user, blob_id, namespace = self._validate(request)
        raw_flags = request.content.read()
        flags = json.loads(raw_flags)
        try:
            self._handler.set_flags(user, blob_id, flags, namespace=namespace)
        except BlobNotFound:
            # 404 - Not Found
            request.setResponseCode(404)
            return "Blob doesn't exists: %s" % blob_id
        except InvalidFlag as e:
            request.setResponseCode(406)
            flag = e.message
            return "Invalid flag: %s" % str(flag)
        return ''

    def _error(self, e, request):
        logger.error('Error processing request: %s' % e.getErrorMessage())
        request.setResponseCode(500)
        request.finish()

    def _validate(self, request):
        for arg in request.postpath:
            if arg and not VALID_STRINGS.match(arg):
                raise Exception('Invalid blob resource argument: %s' % arg)
        namespace = request.args.get('namespace', ['default'])[0]
        if namespace and not VALID_STRINGS.match(namespace):
            raise Exception('Invalid blob namespace: %s' % namespace)
        return request.postpath + [namespace]


if __name__ == '__main__':
    # A dummy blob server
    # curl -X PUT --data-binary @/tmp/book.pdf localhost:9000/user/someid
    # curl -X GET -o /dev/null localhost:9000/user/somerandomstring
    from twisted.python import log
    import sys
    log.startLogging(sys.stdout)

    from twisted.web.server import Site
    from twisted.internet import reactor

    # parse command line arguments
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('--port', default=9000, type=int)
    parser.add_argument('--path', default='/tmp/blobs/user')
    args = parser.parse_args()

    root = BlobsResource("filesystem", args.path)
    # I picture somethink like
    # BlobsResource(backend="filesystem", backend_opts={'path': '/tmp/blobs'})

    factory = Site(root)
    reactor.listenTCP(args.port, factory)
    reactor.run()


class BlobsServerState(object):
    """
    Given a backend name, it gives a instance of IBlobsBackend
    """
    # Allowed backend classes are defined here
    handlers = {"filesystem": FilesystemBlobsBackend}

    def __init__(self, backend, **backend_kwargs):
        if backend not in self.handlers:
            raise ImproperlyConfiguredException("No such backend: %s", backend)
        self.backend = self.handlers[backend](**backend_kwargs)

    def open_database(self, user_id):
        """
        That method is just for compatibility with CouchServerState, so
        IncomingAPI can change backends.
        """
        # TODO: deprecate/refactor it as it's here for compatibility.
        return self.backend
