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


CONFIG_DEFAULTS = {
    'soledad-server': {
        'couch_url': 'http://localhost:5984',
        'create_cmd': None,
        'admin_netrc': '/etc/couchdb/couchdb-admin.netrc',
        'batching': True
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
