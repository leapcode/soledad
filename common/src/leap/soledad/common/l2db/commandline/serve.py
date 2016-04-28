# Copyright 2011 Canonical Ltd.
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

"""Build server for u1db-serve."""
import os

from paste import httpserver

from u1db.remote import (
    http_app,
    server_state,
    cors_middleware
    )


class DbListingServerState(server_state.ServerState):
    """ServerState capable of listing dbs."""

    def global_info(self):
        """Return list of dbs."""
        dbs = []
        for fname in os.listdir(self._workingdir):
            p = os.path.join(self._workingdir, fname)
            if os.path.isfile(p) and os.access(p, os.R_OK|os.W_OK):
                try:
                    with open(p, 'rb') as f:
                        header = f.read(16)
                    if header == "SQLite format 3\000":
                        dbs.append(fname)
                except IOError:
                    pass
        return {"databases": dict.fromkeys(dbs), "db_count": len(dbs)}


def make_server(host, port, working_dir, accept_cors_connections=None):
    """Make a server on host and port exposing dbs living in working_dir."""
    state = DbListingServerState()
    state.set_workingdir(working_dir)
    application = http_app.HTTPApp(state)
    if accept_cors_connections:
        application = cors_middleware.CORSMiddleware(application,
                                                     accept_cors_connections)
    server = httpserver.WSGIServer(application, (host, port),
                                   httpserver.WSGIHandler)
    return server
