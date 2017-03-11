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
"""
from twisted.web import resource

from ._config import get_config


__all__ = ['BlobsResource', 'blobs_resource']


class BlobsResource(resource.Resource):

    isLeaf = True

    def __init__(self, blobs_path):
        resource.Resource.__init__(self)
        self._blobs_path = blobs_path

    def render_GET(self, request):
        return 'blobs is not implemented yet!'


# provide a configured instance of the resource
_config = get_config()
_path = _config['blobs_path']

blobs_resource = BlobsResource(_path)
