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

from u1db.remote import http_app

# Keep OpenSSL's tsafe before importing Twisted submodules so we can put
# it back if Twisted==12.0.0 messes with it.
from OpenSSL import tsafe
old_tsafe = tsafe

from twisted import version
if version.base() == "12.0.0":
    # Put OpenSSL's tsafe back into place. This can probably be removed if we
    # come to use Twisted>=12.3.0.
    import sys
    sys.modules['OpenSSL.tsafe'] = old_tsafe

from leap.soledad.server.auth import SoledadTokenAuthMiddleware
from leap.soledad.server.gzip_middleware import GzipMiddleware
from leap.soledad.server.lock_resource import LockResource

from leap.soledad.common import SHARED_DB_NAME
from leap.soledad.common.couch import CouchServerState


#-----------------------------------------------------------------------------
# Soledad WSGI application
#-----------------------------------------------------------------------------

class SoledadApp(http_app.HTTPApp):
    """
    Soledad WSGI application
    """

    SHARED_DB_NAME = SHARED_DB_NAME
    """
    The name of the shared database that holds user's encrypted secrets.
    """

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
        # ensure the shared database exists
        self.state.ensure_database(self.SHARED_DB_NAME)
        return http_app.HTTPApp.__call__(self, environ, start_response)


http_app.url_to_resource.register(LockResource)


#-----------------------------------------------------------------------------
# Auxiliary functions
#-----------------------------------------------------------------------------

def load_configuration(file_path):
    """
    Load server configuration from file.

    @param file_path: The path to the configuration file.
    @type file_path: str

    @return: A dictionary with the configuration.
    @rtype: dict
    """
    conf = {
        'couch_url': 'http://localhost:5984',
    }
    config = configparser.ConfigParser()
    config.read(file_path)
    if 'soledad-server' in config:
        for key in conf:
            if key in config['soledad-server']:
                conf[key] = config['soledad-server'][key]
    # TODO: implement basic parsing/sanitization of options comming from
    # config file.
    return conf


#-----------------------------------------------------------------------------
# Run as Twisted WSGI Resource
#-----------------------------------------------------------------------------

def application(environ, start_response):
    conf = load_configuration('/etc/leap/soledad-server.conf')
    state = CouchServerState(
        conf['couch_url'],
        SoledadApp.SHARED_DB_NAME,
        SoledadTokenAuthMiddleware.TOKENS_DB)
    # WSGI application that may be used by `twistd -web`
    application = GzipMiddleware(
        SoledadTokenAuthMiddleware(SoledadApp(state)))

    return application(environ, start_response)


from ._version import get_versions
__version__ = get_versions()['version']
del get_versions
