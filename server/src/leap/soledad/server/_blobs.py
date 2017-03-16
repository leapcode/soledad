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
import commands
import os
import base64

from twisted.web import static
from twisted.web import resource
from twisted.web.client import FileBodyProducer
from twisted.web.server import NOT_DONE_YET

from zope.interface import Interface, implementer
from leap.soledad.server._config import get_config


__all__ = ['BlobsResource', 'blobs_resource']


# TODO some error handling needed
# [ ] make path configurable
# [ ] sanitize path

# for the future:
# [ ] isolate user avatar in a safer way
# [ ] catch timeout in the server (and delete incomplete upload)
# p [ chunking (should we do it on the client or on the server?)


class BlobAlreadyExists(Exception):
    pass


class IBlobsBackend(Interface):

    """
    An interface for a BlobsBackend.
    """

    def read_blob(user, blob_id, request):
        """
        Read blob with a given blob_id, and write it to the passed request.

        :returns: a deferred that fires upon finishing.
        """

    def tag_header(user, blob_id, request):
        """
        Adds a header 'Tag' with the last 20 bytes of the encoded file,
        which contains the tag.

        :returns: a deferred that fires upon finishing.
        """

    def write_blob(user, blob_id, request):
        """
        Write blob to the storage, reading it from the passed request.

        :returns: a deferred that fires upon finishing.
        """

    # other stuff for the API

    def delete_blob(user, blob_id):
        pass

    def get_blob_size(user, blob_id):
        pass

    def get_total_storage(user):
        pass


@implementer(IBlobsBackend)
class FilesystemBlobsBackend(object):

    path = '/tmp/blobs/'
    quota = 200 * 1024  # in KB

    def tag_header(self, user, blob_id, request):
        with open(self._get_path(user, blob_id)) as doc_file:
                doc_file.seek(-16, 2)
                tag = base64.urlsafe_b64encode(doc_file.read())
                request.responseHeaders.setRawHeaders('Tag', [tag])

    def read_blob(self, user, blob_id, request):
        print "USER", user
        print "BLOB_ID", blob_id
        path = self._get_path(user, blob_id)
        print "READ FROM", path
        _file = static.File(path, defaultType='application/octet-stream')
        return _file.render_GET(request)

    def write_blob(self, user, blob_id, request):
        path = self._get_path(user, blob_id)
        if os.path.isfile(path):
            # XXX return some 5xx code
            raise BlobAlreadyExists()
        used = self.get_total_storage(user)
        if used > self.quota:
            print "Error 507: Quota exceeded for user:", user
            request.setResponseCode(507)
            request.write('Quota Exceeded!')
            request.finish()
            return NOT_DONE_YET
        try:
            os.makedirs(os.path.split(path)[0])
        except:
            pass
        print "WRITE TO", path
        fbp = FileBodyProducer(request.content)
        d = fbp.startProducing(open(path, 'wb'))
        d.addCallback(lambda _: request.finish())
        return NOT_DONE_YET

    def get_total_storage(self, user):
        return self._get_disk_usage(os.path.join(self.path, user))

    def delete_blob(user, blob_id):
        raise NotImplementedError

    def get_blob_size(user, blob_id):
        raise NotImplementedError

    def _get_disk_usage(self, start_path):
        assert os.path.isdir(start_path)
        cmd = 'du -c %s | tail -n 1' % start_path
        size = commands.getoutput(cmd).split()[0]
        return int(size)

    def _get_path(self, user, blob_id):
        parts = [user]
        parts += [blob_id[0], blob_id[0:3], blob_id[0:6]]
        parts += [blob_id]
        return os.path.join(self.path, *parts)


class BlobsResource(resource.Resource):

    isLeaf = True

    # Allowed factory classes are defined here
    blobsFactoryClass = FilesystemBlobsBackend

    def __init__(self, blobs_path):
        # TODO pass the backend as configurable option
        """
        __init__(self, backend, opts={})
        factorykls = getattr(self, backend + 'Class')(**opts)
        self._handler = kls()
        """
        resource.Resource.__init__(self)
        self._blobs_path = blobs_path
        self._handler = self.blobsFactoryClass()
        assert IBlobsBackend.providedBy(self._handler)

    # TODO double check credentials, we can have then
    # under request.

    def render_GET(self, request):
        print "GETTING", request.path
        user, blob_id = self._split_path(request.path)
        self._handler.tag_header(user, blob_id, request)
        return self._handler.read_blob(user, blob_id, request)

    def render_PUT(self, request):
        user, blob_id = self._split_path(request.path)
        return self._handler.write_blob(user, blob_id, request)

    def _split_path(self, blob_id):
        # FIXME catch errors here
        parts = blob_id.split('/')
        _, user, blobname = parts
        return user, blobname


# provide a configured instance of the resource
_config = get_config()
_path = _config['blobs_path']

blobs_resource = BlobsResource(_path)
if __name__ == '__main__':
    # A dummy blob server
    # curl -X PUT --data-binary @/tmp/book.pdf localhost:9000/user/someid
    # curl -X GET -o /dev/null localhost:9000/user/somerandomstring

    from twisted.web.server import Site
    from twisted.internet import reactor

    # parse command line arguments
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('--port', default=9000)
    parser.add_argument('--path', default='/tmp/blobs/user')
    args = parser.parse_args()

    if not os.path.isdir(args.path):
        os.makedirs(args.path)

    root = BlobsResource(args.path)
    # I picture somethink like
    # BlobsResource(backend="filesystem", backend_opts={'path': '/tmp/blobs'})

    factory = Site(root)
    reactor.listenTCP(args.port, factory)
    reactor.run()
