# -*- coding: utf-8 -*-
# server.py
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
A U1DB server that stores data using CouchDB as its persistence layer.

General information
===================

This is written as a Twisted application and intended to be run using the
twistd command. To start the soledad server, run:

    twistd -n web --wsgi=leap.soledad.server.application --port=X

An initscript is included and will be installed system wide to make it
feasible to start and stop the Soledad server service using a standard
interface.

Server database organization
============================

Soledad Server works with one database per user and one shared database in
which user's encrypted secrets might be stored.

User database
-------------

Users' databases in the server are named 'user-<uuid>' and Soledad Client
may perform synchronization between its local replicas and the user's
database in the server. Authorization for creating, updating, deleting and
retrieving information about the user database as well as performing
synchronization is handled by the `leap.soledad.server.auth` module.

Shared database
---------------

Each user may store password-encrypted recovery data in the shared database,
as well as obtain a lock on the shared database in order to prevent creation
of multiple secrets in parallel.

Recovery documents are stored in the database without any information that
may identify the user. In order to achieve this, the doc_id of recovery
documents are obtained as a hash of the user's uid and the user's password.
User's must have a valid token to interact with recovery documents, but the
server does not perform further authentication because it has no way to know
which recovery document belongs to each user.

This has some implications:

  * The security of the recovery document doc_id, and thus of access to the
    recovery document (encrypted) content, as well as tampering with the
    stored data, all rely on the difficulty of obtaining the user's password
    (supposing the user's uid is somewhat public) and the security of the hash
    function used to calculate the doc_id.

  * The security of the content of a recovery document relies on the
    difficulty of obtaining the user's password.

  * If the user looses his/her password, he/she will not be able to obtain the
    recovery document.

  * Because of the above, it is recommended that recovery documents expire
    (not implemented yet) to prevent excess storage.

Lock documents, on the other hand, may be more thoroughly protected by the
server. Their doc_id's are calculated from the SHARED_DB_LOCK_DOC_ID_PREFIX
and the user's uid.

The authorization for creating, updating, deleting and retrieving recovery
and lock documents on the shared database is handled by
`leap.soledad.server.auth` module.
"""

import configparser
import urlparse
import sys

from u1db.remote import http_app, utils

from ._version import get_versions

from leap.soledad.server.auth import SoledadTokenAuthMiddleware
from leap.soledad.server.gzip_middleware import GzipMiddleware
from leap.soledad.server.lock_resource import LockResource
from leap.soledad.server.sync import (
    SyncResource,
    MAX_REQUEST_SIZE,
    MAX_ENTRY_SIZE,
)

from leap.soledad.common import SHARED_DB_NAME
from leap.soledad.common.backend import SoledadBackend
from leap.soledad.common.couch.state import CouchServerState

# ----------------------------------------------------------------------------
# Soledad WSGI application
# ----------------------------------------------------------------------------


class SoledadApp(http_app.HTTPApp):
    """
    Soledad WSGI application
    """

    SHARED_DB_NAME = SHARED_DB_NAME
    """
    The name of the shared database that holds user's encrypted secrets.
    """

    max_request_size = MAX_REQUEST_SIZE * 1024 * 1024
    max_entry_size = MAX_ENTRY_SIZE * 1024 * 1024

    def __call__(self, environ, start_response):
        """
        Handle a WSGI call to the Soledad application.

        @param environ: Dictionary containing CGI variables.
        @type environ: dict
        @param start_response: Callable of the form start_response(status,
            response_headers, exc_info=None).
        @type start_response: callable

        @return: HTTP application results.
        @rtype: list
        """
        return http_app.HTTPApp.__call__(self, environ, start_response)


# ----------------------------------------------------------------------------
# WSGI resources registration
# ----------------------------------------------------------------------------

# monkey patch u1db with a new resource map
http_app.url_to_resource = http_app.URLToResource()

# register u1db unmodified resources
http_app.url_to_resource.register(http_app.GlobalResource)
http_app.url_to_resource.register(http_app.DatabaseResource)
http_app.url_to_resource.register(http_app.DocsResource)
http_app.url_to_resource.register(http_app.DocResource)

# register Soledad's new or modified resources
http_app.url_to_resource.register(LockResource)
http_app.url_to_resource.register(SyncResource)


# ----------------------------------------------------------------------------
# Modified HTTP method invocation (to account for splitted sync)
# ----------------------------------------------------------------------------

class HTTPInvocationByMethodWithBody(
        http_app.HTTPInvocationByMethodWithBody):
    """
    Invoke methods on a resource.
    """

    def __call__(self):
        """
        Call an HTTP method of a resource.

        This method was rewritten to allow for a sync flow which uses one POST
        request for each transferred document (back and forth).

        Usual U1DB sync process transfers all documents from client to server
        and back in only one POST request. This is inconvenient for some
        reasons, as lack of possibility of gracefully interrupting the sync
        process, and possible timeouts for when dealing with large documents
        that have to be retrieved and encrypted/decrypted. Because of those,
        we split the sync process into many POST requests.
        """
        args = urlparse.parse_qsl(self.environ['QUERY_STRING'],
                                  strict_parsing=False)
        try:
            args = dict(
                (k.decode('utf-8'), v.decode('utf-8')) for k, v in args)
        except ValueError:
            raise http_app.BadRequest()
        method = self.environ['REQUEST_METHOD'].lower()
        if method in ('get', 'delete'):
            meth = self._lookup(method)
            return meth(args, None)
        else:
            # we expect content-length > 0, reconsider if we move
            # to support chunked enconding
            try:
                content_length = int(self.environ['CONTENT_LENGTH'])
            except (ValueError, KeyError):
                raise http_app.BadRequest
            if content_length <= 0:
                raise http_app.BadRequest
            if content_length > self.max_request_size:
                raise http_app.BadRequest
            reader = http_app._FencedReader(
                self.environ['wsgi.input'], content_length,
                self.max_entry_size)
            content_type = self.environ.get('CONTENT_TYPE')
            if content_type == 'application/json':
                meth = self._lookup(method)
                body = reader.read_chunk(sys.maxint)
                return meth(args, body)
            elif content_type.startswith('application/x-soledad-sync'):
                # read one line and validate it
                body_getline = reader.getline
                if body_getline().strip() != '[':
                    raise http_app.BadRequest()
                line = body_getline()
                line, comma = utils.check_and_strip_comma(line.strip())
                meth_args = self._lookup('%s_args' % method)
                meth_args(args, line)
                # handle incoming documents
                if content_type == 'application/x-soledad-sync-put':
                    meth_put = self._lookup('%s_put' % method)
                    meth_end = self._lookup('%s_end' % method)
                    entries = []
                    while True:
                        line = body_getline()
                        entry = line.strip()
                        if entry == ']':  # end of incoming document stream
                            break
                        if not entry or not comma:  # empty or no prec comma
                            raise http_app.BadRequest
                        entry, comma = utils.check_and_strip_comma(entry)
                        entries.append(entry)
                    if comma or body_getline():  # extra comma or data
                        raise http_app.BadRequest
                    for entry in entries:
                        meth_put({}, entry)
                    return meth_end()
                # handle outgoing documents
                elif content_type == 'application/x-soledad-sync-get':
                    line = body_getline()
                    entry = line.strip()
                    meth_get = self._lookup('%s_get' % method)
                    return meth_get({}, line)
                else:
                    raise http_app.BadRequest()
            else:
                raise http_app.BadRequest()


# monkey patch server with new http invocation
http_app.HTTPInvocationByMethodWithBody = HTTPInvocationByMethodWithBody


# ----------------------------------------------------------------------------
# Auxiliary functions
# ----------------------------------------------------------------------------
CONFIG_DEFAULTS = {
    'soledad-server': {
        'couch_url': 'http://localhost:5984',
        'create_cmd': None,
        'admin_netrc': '/etc/couchdb/couchdb-admin.netrc',
        'batching': False
    },
    'database-security': {
        'members': ['soledad'],
        'members_roles': [],
        'admins': [],
        'admins_roles': []
    }
}


def load_configuration(file_path):
    """
    Load server configuration from file.

    @param file_path: The path to the configuration file.
    @type file_path: str

    @return: A dictionary with the configuration.
    @rtype: dict
    """
    defaults = dict(CONFIG_DEFAULTS)
    config = configparser.SafeConfigParser()
    config.read(file_path)
    for section in defaults:
        if not config.has_section(section):
            continue
        for key, value in defaults[section].items():
            if not config.has_option(section, key):
                continue
            elif type(value) == bool:
                defaults[section][key] = config.getboolean(section, key)
            elif type(value) == list:
                values = config.get(section, key).split(',')
                values = [v.strip() for v in values]
                defaults[section][key] = values
            else:
                defaults[section][key] = config.get(section, key)
    # TODO: implement basic parsing/sanitization of options comming from
    # config file.
    return defaults


# ----------------------------------------------------------------------------
# Run as Twisted WSGI Resource
# ----------------------------------------------------------------------------

def application(environ, start_response):
    conf = load_configuration('/etc/soledad/soledad-server.conf')
    conf = conf['soledad-server']
    state = CouchServerState(conf['couch_url'], create_cmd=conf['create_cmd'])
    SoledadBackend.BATCH_SUPPORT = conf['batching']
    # WSGI application that may be used by `twistd -web`
    application = GzipMiddleware(
        SoledadTokenAuthMiddleware(SoledadApp(state)))

    return application(environ, start_response)

__version__ = get_versions()['version']
del get_versions
