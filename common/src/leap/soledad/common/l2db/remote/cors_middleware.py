# Copyright 2012 Canonical Ltd.
#
# This file is part of u1db.
#
# u1db is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# u1db is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with u1db.  If not, see <http://www.gnu.org/licenses/>.
"""U1DB Cross-Origin Resource Sharing WSGI middleware."""


class CORSMiddleware(object):
    """U1DB Cross-Origin Resource Sharing WSGI middleware."""

    def __init__(self, app, accept_cors_connections):
        self.origins = ' '.join(accept_cors_connections)
        self.app = app

    def _cors_headers(self):
        return [('access-control-allow-origin', self.origins),
                ('access-control-allow-headers',
                 'authorization, content-type, x-requested-with'),
                ('access-control-allow-methods',
                 'GET, POST, PUT, DELETE, OPTIONS')]

    def __call__(self, environ, start_response):
        def wrap_start_response(status, headers, exc_info=None):
            headers += self._cors_headers()
            return start_response(status, headers, exc_info)

        if environ['REQUEST_METHOD'].lower() == 'options':
            wrap_start_response("200 OK", [('content-type', 'text/plain')])
            return ['']

        return self.app(environ, wrap_start_response)
