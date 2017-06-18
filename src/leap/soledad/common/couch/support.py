# -*- coding: utf-8 -*-
# support.py
# Copyright (C) 2015 LEAP
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
import sys


"""
Monkey patches and temporary code that may be removed with version changes.
"""


# for bigcouch
# TODO: Remove if bigcouch support is dropped
class MultipartWriter(object):

    """
    A multipart writer adapted from python-couchdb's one so we can PUT
    documents using couch's multipart PUT.

    This stripped down version does not allow for nested structures, and
    contains only the essential things we need to PUT SoledadDocuments to the
    couch backend. Also, please note that this is a patch. The couchdb lib has
    another implementation that works fine with CouchDB 1.6, but removing this
    now will break compatibility with bigcouch.
    """

    CRLF = '\r\n'

    def __init__(self, fileobj, headers=None, boundary=None):
        """
        Initialize the multipart writer.
        """
        self.fileobj = fileobj
        if boundary is None:
            boundary = self._make_boundary()
        self._boundary = boundary
        self._build_headers('related', headers)

    def add(self, mimetype, content, headers={}):
        """
        Add a part to the multipart stream.
        """
        self.fileobj.write('--')
        self.fileobj.write(self._boundary)
        self.fileobj.write(self.CRLF)
        headers['Content-Type'] = mimetype
        self._write_headers(headers)
        if content:
            # XXX: throw an exception if a boundary appears in the content??
            self.fileobj.write(content)
            self.fileobj.write(self.CRLF)

    def close(self):
        """
        Close the multipart stream.
        """
        self.fileobj.write('--')
        self.fileobj.write(self._boundary)
        # be careful not to have anything after '--', otherwise old couch
        # versions (including bigcouch) will fail.
        self.fileobj.write('--')

    def _make_boundary(self):
        """
        Create a boundary to discern multi parts.
        """
        try:
            from uuid import uuid4
            return '==' + uuid4().hex + '=='
        except ImportError:
            from random import randrange
            token = randrange(sys.maxint)
            format = '%%0%dd' % len(repr(sys.maxint - 1))
            return '===============' + (format % token) + '=='

    def _write_headers(self, headers):
        """
        Write a part header in the buffer stream.
        """
        if headers:
            for name in sorted(headers.keys()):
                value = headers[name]
                self.fileobj.write(name)
                self.fileobj.write(': ')
                self.fileobj.write(value)
                self.fileobj.write(self.CRLF)
        self.fileobj.write(self.CRLF)

    def _build_headers(self, subtype, headers):
        """
        Build the main headers of the multipart stream.

        This is here so we can send headers separete from content using
        python-couchdb API.
        """
        self.headers = {}
        self.headers['Content-Type'] = 'multipart/%s; boundary="%s"' % \
                                       (subtype, self._boundary)
        if headers:
            for name in sorted(headers.keys()):
                value = headers[name]
                self.headers[name] = value
