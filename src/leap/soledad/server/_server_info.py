# -*- coding: utf-8 -*-
# _server_info.py
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
Resource that announces information about the server.
"""
import json

from twisted.web.resource import Resource

from leap.soledad import __version__


__all__ = ['ServerInfo']


class ServerInfo(Resource):
    """
    Return information about the server.
    """

    isLeaf = True

    def __init__(self, blobs_enabled):
        self._info = {
            "blobs": blobs_enabled,
            "version": __version__
        }

    def render_GET(self, request):
        return json.dumps(self._info)
