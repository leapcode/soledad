# -*- coding: utf-8 -*-
# config.py
# Copyright (C) 2016 LEAP
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


import configparser
import os

from twisted.logger import Logger


__all__ = ['get_config']

logger = Logger()

# make sure to update documentation if this default is changed.
DEFAULT_CONFIG_FILE = '/etc/soledad/soledad-server.conf'
CONFIG_DEFAULTS = {
    'soledad-server': {
        'couch_url': 'http://localhost:5984',
        'create_cmd': None,
        'admin_netrc': '/etc/couchdb/couchdb-admin.netrc',
        'batching': True,
        'blobs': False,
        'blobs_path': '/var/lib/soledad/blobs',
        'services_tokens_file': '/etc/soledad/services.tokens',
        'concurrent_blob_writes': 50,
    },
    'database-security': {
        'members': ['soledad'],
        'members_roles': [],
        'admins': [],
        'admins_roles': []
    }
}


def _load_from_file(file_path):
    logger.info('Loading configuration from %s' % file_path)
    conf = dict(CONFIG_DEFAULTS)
    parsed = configparser.SafeConfigParser()
    parsed.read(file_path)
    for section in conf:
        if not parsed.has_section(section):
            continue
        for key, value in conf[section].items():
            if not parsed.has_option(section, key):
                continue
            elif type(value) == bool:
                conf[section][key] = parsed.getboolean(section, key)
            elif type(value) == list:
                values = parsed.get(section, key).split(',')
                values = [v.strip() for v in values]
                conf[section][key] = values
            else:
                conf[section][key] = parsed.get(section, key)
    # TODO: implement basic parsing/sanitization of options comming from
    # parsed file.
    return conf


def _reflect_environment(conf):
    from_environment = ['couch_url']
    for option in from_environment:
        name = 'SOLEDAD_%s' % option.upper()
        value = os.environ.get(name)
        if value:
            logger.info('Using %s=%s because of %s environment variable.'
                        % (option, value, name))
            conf['soledad-server'][option] = value
    return conf


def _load_config(file_path):
    conf = _load_from_file(file_path)
    conf = _reflect_environment(conf)
    return conf


_config = None


def get_config(section='soledad-server'):
    global _config
    if not _config:
        fname = os.environ.get(
            'SOLEDAD_SERVER_CONFIG_FILE', DEFAULT_CONFIG_FILE)
        _config = _load_config(fname)
    return _config[section]
