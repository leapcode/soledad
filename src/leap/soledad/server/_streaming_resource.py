# -*- coding: utf-8 -*-
# _streaming_resource.py
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
A twisted resource that serves download as a single stream of multiple blobs.
-> POST .../uuid/ DATA: [blob_id, blob_id2, ..., blob_idn]
<- [(size(blob_id), content(blob_id)) for blob_id in DATA] (as a binary stream)
"""
import json
import base64

from zope.interface import implementer
from twisted.internet.interfaces import IPushProducer
from twisted.internet import task, defer
from twisted.web.server import NOT_DONE_YET
from twisted.web.resource import Resource

from leap.soledad.common.log import getLogger
from . import interfaces
from ._blobs import FilesystemBlobsBackend
from ._blobs import ImproperlyConfiguredException


__all__ = ['StreamingResource']


logger = getLogger(__name__)


class StreamingResource(Resource):
    isLeaf = True

    # Allowed backend classes are defined here
    handlers = {"filesystem": FilesystemBlobsBackend}

    def __init__(self, backend, blobs_path, **backend_kwargs):
        Resource.__init__(self)
        self._blobs_path = blobs_path
        backend_kwargs.update({'blobs_path': blobs_path})
        if backend not in self.handlers:
            raise ImproperlyConfiguredException("No such backend: %s", backend)
        self._handler = self.handlers[backend](**backend_kwargs)
        assert interfaces.IBlobsBackend.providedBy(self._handler)

    def render_POST(self, request):
        user = request.postpath[0]
        namespace = request.args.get('namespace', ['default'])[0]
        db = self._handler
        raw_content = request.content.read()
        blob_ids = json.loads(raw_content)
        deferreds = []
        for blob_id in blob_ids:

            def _get_blob_info(blob_id, path):
                d = db.get_blob_size(user, blob_id, namespace)
                d.addCallback(lambda size: (blob_id, path, size))
                return d

            path = db._get_path(user, blob_id, namespace)
            d = _get_blob_info(blob_id, path)
            deferreds.append(d)
        d = defer.gatherResults(deferreds)
        d.addCallback(
            lambda paths: DownstreamProducer(request, paths).start())
        return NOT_DONE_YET


@implementer(IPushProducer)
class DownstreamProducer(object):
    chunk_size = 2**14

    def __init__(self, request, paths):
        self.request = request
        self.paths = paths

    def start(self):
        iterator = self._gen_data()
        self.task = task.cooperate(iterator)
        self.request.registerProducer(self, streaming=True)

    def resumeProducing(self):
        return self.task.resume()

    def pauseProducing(self):
        return self.task.pause()

    def _gen_data(self):
        request, paths = self.request, self.paths
        while paths:
            blob_id, path, size = paths.pop(0)
            request.write('%08x' % size)  # sends file size
            with open(path, 'rb') as blob_fd:
                blob_fd.seek(-16, 2)
                encoded_tag = base64.urlsafe_b64encode(blob_fd.read())
                request.write(encoded_tag)  # sends AES-GCM tag
                blob_fd.seek(0)
                request.write(' ')
                data = blob_fd.read(self.chunk_size)
                while data:
                    yield
                    request.write(data)
                    data = blob_fd.read(self.chunk_size)
        request.unregisterProducer()
        request.finish()

    def stopProducing(self):
        self.request = None
        return self.task.stop()
