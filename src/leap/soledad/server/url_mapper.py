# -*- coding: utf-8 -*-
# url_mapper.py
# Copyright (C) 2013 LEAP
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
An URL mapper that represents authorized paths.
"""
from routes.mapper import Mapper

from leap.soledad.common import SHARED_DB_NAME
from leap.soledad.common.l2db import DBNAME_CONSTRAINTS


class URLMapper(object):
    """
    Maps the URLs users can access.
    """

    def __init__(self):
        self._map = Mapper(controller_scan=None)
        self._connect_urls()
        self._map.create_regs()

    def match(self, path, method):
        environ = {'PATH_INFO': path, 'REQUEST_METHOD': method}
        return self._map.match(environ=environ)

    def _connect(self, pattern, http_methods):
        self._map.connect(
            None, pattern, http_methods=http_methods,
            conditions=dict(method=http_methods),
            requirements={'dbname': DBNAME_CONSTRAINTS})

    def _connect_urls(self):
        """
        Register the authorization info in the mapper using C{SHARED_DB_NAME}
        as the user's database name.

        This method sets up the following authorization rules:

            URL path                        | Authorized actions
            ----------------------------------------------------
            /                               | GET
            /robots.txt                     | GET
            /shared-db                      | GET
            /shared-db/doc/{any_id}         | GET, PUT, DELETE
            /user-{uuid}/sync-from/{source} | GET, PUT, POST
            /blobs/{uuid}/{blob_id}         | GET, PUT, POST
            /blobs/{uuid}                   | GET
            /incoming/                      | PUT
        """
        # auth info for global resource
        self._connect('/', ['GET'])
        # robots
        self._connect('/robots.txt', ['GET'])
        # auth info for shared-db database resource
        self._connect('/%s' % SHARED_DB_NAME, ['GET'])
        # auth info for shared-db doc resource
        self._connect('/%s/doc/{id:.*}' % SHARED_DB_NAME,
                      ['GET', 'PUT', 'DELETE'])
        # auth info for user-db sync resource
        self._connect('/user-{uuid}/sync-from/{source_replica_uid}',
                      ['GET', 'PUT', 'POST'])
        # auth info for blobs resource
        self._connect('/blobs/{uuid}/{blob_id}', ['GET', 'PUT'])
        self._connect('/blobs/{uuid}', ['GET'])

        # incoming resource
        self._connect('/incoming/{uuid}/{incoming_id}', ['PUT'])
