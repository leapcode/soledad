# -*- coding: utf-8 -*-
# _blobs/__init__.py
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
from .fs_backend import FilesystemBlobsBackend
from .resource import BlobsResource
from .state import BlobsServerState
from .errors import BlobExists
from .errors import QuotaExceeded
from .errors import ImproperlyConfiguredException


__all__ = [
    'FilesystemBlobsBackend',
    'BlobsResource',
    'BlobsServerState',
    'BlobExists',
    'QuotaExceeded',
    'ImproperlyConfiguredException',
]


if __name__ == '__main__':
    # A dummy blob server
    # curl -X PUT --data-binary @/tmp/book.pdf localhost:9000/user/someid
    # curl -X GET -o /dev/null localhost:9000/user/somerandomstring
    from twisted.python import log
    import sys
    log.startLogging(sys.stdout)

    from twisted.web.server import Site
    from twisted.internet import reactor

    import argparse

    # parse command line
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', default=9000, type=int)
    parser.add_argument('--path', default='/tmp/blobs/user')
    args = parser.parse_args()

    # run the server
    root = BlobsResource("filesystem", args.path)
    factory = Site(root)
    reactor.listenTCP(args.port, factory)
    reactor.run()
