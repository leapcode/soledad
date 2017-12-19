# -*- coding: utf-8 -*-
# _blobs/resource.py
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
A Twisted Web resource for blobs.
"""
import json

from twisted.web import resource
from twisted.web.client import FileBodyProducer
from twisted.web.server import NOT_DONE_YET

from leap.soledad.common.blobs import InvalidFlag
from leap.soledad.server import interfaces

from .fs_backend import FilesystemBlobsBackend
from .errors import BlobNotFound
from .errors import BlobExists
from .errors import ImproperlyConfiguredException
from .errors import QuotaExceeded
from .util import VALID_STRINGS

from leap.soledad.common.log import getLogger


logger = getLogger(__name__)


def _catchBlobNotFound(failure, request, user, blob_id):
    failure.trap(BlobNotFound)
    logger.error("Error 404: Blob %s does not exist for user %s"
                 % (blob_id, user))
    request.setResponseCode(404)
    request.write("Blob doesn't exists: %s" % blob_id)
    request.finish()


def _catchBlobExists(failure, request, user, blob_id):
    failure.trap(BlobExists)
    logger.error("Error 409: Blob %s already exists for user %s"
                 % (blob_id, user))
    request.setResponseCode(409)
    request.write("Blob already exists: %s" % blob_id)
    request.finish()


def _catchQuotaExceeded(failure, request, user):
    failure.trap(QuotaExceeded)
    logger.error("Error 507: Quota exceeded for user: %s" % user)
    request.setResponseCode(507)
    request.write('Quota Exceeded!')
    request.finish()


def _catchInvalidFlag(failure, request, user, blob_id):
    failure.trap(InvalidFlag)
    flag = failure.value.message
    logger.error("Error 406: Attempted to set invalid flag %s for blob %s "
                 "for user %s" % (flag, blob_id, user))
    request.setResponseCode(406)
    request.write("Invalid flag: %s" % str(flag))
    request.finish()


def _catchAllErrors(self, e, request):
    logger.error('Error processing request: %s' % e.getErrorMessage())
    request.setResponseCode(500)
    request.finish()


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

    def _only_count(self, request, user, namespace):
        d = self._handler.count(user, namespace)
        d.addCallback(lambda count: json.dumps({"count": count}))
        d.addCallback(lambda count: request.write(count))
        d.addCallback(lambda _: request.finish())
        return NOT_DONE_YET

    def _list(self, request, user, namespace):
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

    def _only_flags(self, request, user, blob_id, namespace):
        d = self._handler.get_flags(user, blob_id, namespace)
        d.addCallback(lambda flags: json.dumps(flags))
        d.addCallback(lambda flags: request.write(flags))
        d.addCallback(lambda _: request.finish())
        d.addErrback(_catchBlobNotFound, request, user, blob_id)
        d.addErrback(_catchAllErrors, request)
        return NOT_DONE_YET

    def _get_blob(self, request, user, blob_id, namespace):

        def _set_tag_header(tag):
            request.responseHeaders.setRawHeaders('Tag', [tag])

        def _read_blob(_):
            handler = self._handler
            consumer = request
            d = handler.read_blob(user, blob_id, consumer, namespace=namespace)
            return d

        d = self._handler.get_tag(user, blob_id, namespace)
        d.addCallback(_set_tag_header)
        d.addCallback(_read_blob)
        d.addCallback(lambda _: request.finish())
        d.addErrback(_catchBlobNotFound, request, user, blob_id)
        d.addErrback(_catchAllErrors, request, finishRequest=True)

        return NOT_DONE_YET

    def render_GET(self, request):
        logger.info("http get: %s" % request.path)
        user, blob_id, namespace = self._validate(request)
        only_flags = request.args.get('only_flags', [False])[0]

        if not blob_id and request.args.get('only_count', [False])[0]:
            return self._only_count(request, user, namespace)

        if not blob_id:
            return self._list(request, user, namespace)

        if only_flags:
            return self._only_flags(request, user, blob_id, namespace)

        return self._get_blob(request, user, blob_id, namespace)

    def render_DELETE(self, request):
        logger.info("http put: %s" % request.path)
        user, blob_id, namespace = self._validate(request)
        d = self._handler.delete_blob(user, blob_id, namespace=namespace)
        d.addCallback(lambda _: request.finish())
        d.addErrback(_catchBlobNotFound, request, user, blob_id)
        d.addErrback(_catchAllErrors, request)
        return NOT_DONE_YET

    def render_PUT(self, request):
        logger.info("http put: %s" % request.path)
        user, blob_id, namespace = self._validate(request)
        producer = FileBodyProducer(request.content)
        handler = self._handler
        d = handler.write_blob(user, blob_id, producer, namespace=namespace)
        d.addCallback(lambda _: request.finish())
        d.addErrback(_catchBlobExists, request, user, blob_id)
        d.addErrback(_catchQuotaExceeded, request, user)
        d.addErrback(_catchAllErrors, request)
        return NOT_DONE_YET

    def render_POST(self, request):
        logger.info("http post: %s" % request.path)
        user, blob_id, namespace = self._validate(request)
        raw_flags = request.content.read()
        flags = json.loads(raw_flags)
        d = self._handler.set_flags(user, blob_id, flags, namespace=namespace)
        d.addCallback(lambda _: request.write(''))
        d.addCallback(lambda _: request.finish())
        d.addErrback(_catchBlobNotFound, request, user, blob_id)
        d.addErrback(_catchInvalidFlag, request, user, blob_id)
        d.addErrback(_catchAllErrors, request)
        return NOT_DONE_YET

    def _validate(self, request):
        for arg in request.postpath:
            if arg and not VALID_STRINGS.match(arg):
                raise Exception('Invalid blob resource argument: %s' % arg)
        namespace = request.args.get('namespace', ['default'])[0]
        if namespace and not VALID_STRINGS.match(namespace):
            raise Exception('Invalid blob namespace: %s' % namespace)
        return request.postpath + [namespace]
