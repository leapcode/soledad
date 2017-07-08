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

from twisted.logger import Logger
from twisted.web import static
from twisted.web import resource
from twisted.web.client import FileBodyProducer
from twisted.web.server import NOT_DONE_YET
from twisted.internet import utils, defer

from zope.interface import implementer

from leap.common.files import mkdir_p
from leap.soledad.server import interfaces


__all__ = ['BlobsResource']


logger = Logger()

# Used for sanitizers, we accept only letters, numbers, '-' and '_'
VALID_STRINGS = re.compile('^[a-zA-Z0-9_-]+$')


# for the future:
# [ ] isolate user avatar in a safer way
# [ ] catch timeout in the server (and delete incomplete upload)
# [ ] chunking (should we do it on the client or on the server?)


@implementer(interfaces.IBlobsBackend)
class FilesystemBlobsBackend(object):

    def __init__(self, blobs_path='/tmp/blobs/', quota=200 * 1024):
        self.quota = quota
        if not os.path.isdir(blobs_path):
            os.makedirs(blobs_path)
        self.path = blobs_path

    def read_blob(self, user, blob_id, request, namespace=''):
        logger.info('reading blob: %s - %s' % (user, blob_id))
        path = self._get_path(user, blob_id, namespace)
        logger.debug('blob path: %s' % path)
        _file = static.File(path, defaultType='application/octet-stream')
        return _file.render_GET(request)

    @defer.inlineCallbacks
    def write_blob(self, user, blob_id, request, namespace=''):
        path = self._get_path(user, blob_id, namespace)
        try:
            mkdir_p(os.path.split(path)[0])
        except OSError:
            pass
        if os.path.isfile(path):
            # 409 - Conflict
            request.setResponseCode(409)
            request.write("Blob already exists: %s" % blob_id)
            defer.returnValue(None)
        used = yield self.get_total_storage(user)
        if used > self.quota:
            logger.error("Error 507: Quota exceeded for user: %s" % user)
            request.setResponseCode(507)
            request.write('Quota Exceeded!')
            defer.returnValue(None)
        logger.info('writing blob: %s - %s' % (user, blob_id))
        fbp = FileBodyProducer(request.content)
        yield fbp.startProducing(open(path, 'wb'))

    def delete_blob(self, user, blob_id, namespace=''):
        blob_path = self._get_path(user, blob_id, namespace)
        os.unlink(blob_path)

    def get_blob_size(user, blob_id, namespace=''):
        raise NotImplementedError

    def list_blobs(self, user, request, namespace='', order_by=None):
        blob_ids = []
        base_path = self._get_path(user, custom_preffix=namespace)
        for root, dirs, filenames in os.walk(base_path):
            blob_ids += [os.path.join(root, name) for name in filenames]
        if order_by in ['date', '+date']:
            blob_ids.sort(key=lambda x: os.path.getmtime(x))
        elif order_by == '-date':
            blob_ids.sort(key=lambda x: os.path.getmtime(x), reverse=True)
        elif order_by:
            raise Exception("Unsupported order_by parameter: %s" % order_by)
        blob_ids = [os.path.basename(path) for path in blob_ids]
        return json.dumps(blob_ids)

    def get_total_storage(self, user):
        return self._get_disk_usage(self._get_path(user))

    def add_tag_header(self, user, blob_id, request, namespace=''):
        with open(self._get_path(user, blob_id, namespace)) as doc_file:
            doc_file.seek(-16, 2)
            tag = base64.urlsafe_b64encode(doc_file.read())
            request.responseHeaders.setRawHeaders('Tag', [tag])

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

    def _get_path(self, user, blob_id='', custom_preffix=''):
        parts = [user]
        parts += self._get_preffix(blob_id, custom_preffix)
        if blob_id:
            parts += [blob_id]
        path = os.path.join(self.path, *parts)
        return self._validate_path(path, user, blob_id)

    def _get_preffix(self, blob_id, custom=''):
        if custom or not blob_id:
            return [custom]
        return [blob_id[0], blob_id[0:3], blob_id[0:6]]


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
        if not blob_id:
            order = request.args.get('order_by', [None])[0]
            return self._handler.list_blobs(user, request, namespace,
                                            order_by=order)
        self._handler.add_tag_header(user, blob_id, request)
        return self._handler.read_blob(user, blob_id, request, namespace)

    def render_DELETE(self, request):
        logger.info("http put: %s" % request.path)
        user, blob_id, namespace = self._validate(request)
        self._handler.delete_blob(user, blob_id, namespace)
        return ''

    def render_PUT(self, request):
        logger.info("http put: %s" % request.path)
        user, blob_id, namespace = self._validate(request)
        d = self._handler.write_blob(user, blob_id, request, namespace)
        d.addCallback(lambda _: request.finish())
        d.addErrback(self._error, request)
        return NOT_DONE_YET

    def _error(self, e, request):
        logger.error('Error processing request: %s' % e.getErrorMessage())
        request.setResponseCode(500)
        request.finish()

    def _validate(self, request):
        for arg in request.postpath:
            if arg and not VALID_STRINGS.match(arg):
                raise Exception('Invalid blob resource argument: %s' % arg)
        namespace = request.args.get('namespace', [''])[0]
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
