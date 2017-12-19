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

from .errors import BlobExists
from .errors import ImproperlyConfiguredException
from .errors import QuotaExceeded


__all__ = ['BlobsResource', 'BlobExists', 'QuotaExceeded']


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
