# -*- coding: utf-8 -*-
# app.py
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
Soledad Server, as a Twisted Application.
"""
import os

from twisted.application import service, strports
from twisted.internet import reactor
from twisted.web import server

from leap.soledad.common.couch.check import check_schema_versions
from leap.soledad.common.log import getLogger
from leap.soledad.server import entrypoints
from leap.soledad.server import get_config


logger = getLogger(__name__)


def _deferred_shutdown(status):
    reactor.addSystemEventTrigger('after', 'shutdown',
                                  os._exit, status)
    reactor.stop()


def _exit(status):
    reactor.callWhenRunning(_deferred_shutdown, status)


def _log_and_exit(failure):
    logger.error('Error while starting up server: %r'
                 % failure.getErrorMessage())
    _exit(20)


#
# necessary checks
#

def check_env(local_port, public_port):
    if local_port == public_port:
        logger.error("LOCAL_SERVICES_PORT and HTTPS_PORT can't be the same!")
        _exit(20)

    if public_port is None and not os.getenv('DEBUG_SERVER'):
        logger.error("HTTPS_PORT env var is required to be set!")
        _exit(20)


def check_conf(conf):
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
        _exit(20)


#
# service creation functions
#

def create_local_service(port, application):
    logger.info('Starting local Services HTTP API')
    desc = 'tcp:%s:interface=127.0.0.1' % port
    site = server.Site(entrypoints.ServicesEntrypoint())
    service = strports.service(desc, site)
    service.setServiceParent(application)


def get_tls_service_description(port):
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


def create_public_service(port, application):
    logger.info('Starting public Users HTTP API')
    if port:
        desc = get_tls_service_description(port)
    else:
        logger.warn('Using plain HTTP on public Users API.')
        desc = 'tcp:port=2424:interface=0.0.0.0'

    site = server.Site(entrypoints.UsersEntrypoint())
    service = strports.service(desc, site)
    service.setServiceParent(application)


def create_services(local_port, public_port, application):
    create_local_service(local_port, application)
    create_public_service(public_port, application)


#
# the application
#

def patch_noisy_factory():
    from twisted.internet.protocol import Factory
    Factory.noisy = False


def run(application):
    patch_noisy_factory()
    local_port = os.getenv('LOCAL_SERVICES_PORT', 2525)
    public_port = os.getenv('HTTPS_PORT', None)
    conf = get_config()
    check_env(local_port, public_port)
    check_conf(conf)
    d = check_schema_versions(conf['couch_url'])
    d.addCallback(lambda _: create_services(local_port, public_port,
                                            application))
    d.addErrback(_log_and_exit)


application = service.Application('soledad-server')
