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
-> POST .../uuid/namespace/ DATA: [blob_id, blob_id2, ..., blob_idn]
<- [(size(blob_id), content(blob_id)) for blob_id in DATA] (as a binary stream)
"""
import json
import struct

from twisted.web.server import NOT_DONE_YET
from twisted.web.resource import Resource

from leap.soledad.common.log import getLogger
from . import interfaces
from ._blobs import FilesystemBlobsBackend
from ._blobs import ImproperlyConfiguredException


__all__ = ['StreamingResource']


logger = getLogger(__name__)
SIZE_PACKER = struct.Struct('<I')


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
        for blob_id in blob_ids:
            path = db._get_path(user, blob_id, namespace)
            size = db.get_blob_size(user, blob_id, namespace)
            request.write(SIZE_PACKER.pack(size))
            with open(path, 'rb') as blob_fd:
                # TODO: use a producer
                blob_fd.seek(-16, 2)
                request.write(blob_fd.read())  # sends tag
                blob_fd.seek(0)
                request.write(' ')
                request.write(blob_fd.read())

        request.finish()
        return NOT_DONE_YET
