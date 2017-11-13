# -*- coding: utf-8 -*-
# server.tac
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
import sys
import os

from twisted.application import service, strports
from twisted.logger import Logger
from twisted.web import server

from leap.soledad.common.couch.check import check_schema_versions
from leap.soledad.server import entrypoints
from leap.soledad.server._wsgi import init_couch_state
from leap.soledad.server._config import get_config


logger = Logger(__name__)


#
# necessary checks
#

def _check_env(local_port, public_port):
    if local_port == public_port:
        logger.error("LOCAL_SERVICES_PORT and HTTPS_PORT can't be the same!")
        sys.exit(20)

    if public_port is None and not os.getenv('DEBUG_SERVER'):
        logger.error("HTTPS_PORT env var is required to be set!")
        sys.exit(20)


def _check_conf(conf):
    path = conf['blobs_path']
    blobs_not_empty = bool(os.path.exists(path) and os.listdir(path))
    if not conf['blobs'] and blobs_not_empty:
        message = """
**  WARNING: Blobs is disabled, but blobs directory isn't empty.          **
**  If it was previously enabled, disabling can cause data loss due blobs **
**  documents not being accessible to users.                              **
**  Blobs directory: %s
**  REFUSING TO START. Please double check your configuration.            **
    """
        logger.error(message % path)
        sys.exit(20)


#
# service creation functions
#

def _create_local_service(port, application):
    logger.info('Starting local Services HTTP API')
    desc = 'tcp:%s:interface=127.0.0.1' % port
    site = server.Site(entrypoints.ServicesEntrypoint())
    service = strports.service(desc, site)
    service.setServiceParent(application)


def _get_tls_service_description(port):
    privateKey = os.getenv('PRIVKEY_PATH', '/etc/soledad/soledad-server.key')
    certKey = os.getenv('CERT_PATH', '/etc/soledad/soledad-server.pem')
    sslmethod = os.getenv('SSL_METHOD', 'SSLv23_METHOD')
    desc = ':'.join([
        'ssl',
        'port=' + str(port),
        'privateKey=' + privateKey,
        'certKey=' + certKey,
        'sslmethod=' + sslmethod])
    return desc


def _create_public_service(port, application):
    logger.info('Starting public Users HTTP API')
    if port:
        desc = _get_tls_service_description(port)
    else:
        logger.warn('Using plain HTTP on public Users API.')
        desc = 'tcp:port=2424:interface=0.0.0.0'

    site = server.Site(entrypoints.UsersEntrypoint())
    service = strports.service(desc, site)
    service.setServiceParent(application)


def _create_services(local_port, public_port, application):
    _create_local_service(local_port, application)
    _create_public_service(public_port, application)


#
# the application
#

def _run(application):
    local_port = os.getenv('LOCAL_SERVICES_PORT', 2525)
    public_port = os.getenv('HTTPS_PORT', None)
    conf = get_config()
    _check_env(local_port, public_port)
    _check_conf(conf)
    d = check_schema_versions(conf['couch_url'])
    d.addCallback(lambda _: init_couch_state(conf))
    d.addCallback(lambda _: _create_services(local_port, public_port,
                                             application))


application = service.Application('soledad-server')
_run(application)
