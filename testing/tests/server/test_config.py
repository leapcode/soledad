# -*- coding: utf-8 -*-
# test_config.py
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
Tests for server configuration.
"""

from twisted.trial import unittest
from pkg_resources import resource_filename

from leap.soledad.server._config import _load_config
from leap.soledad.server._config import CONFIG_DEFAULTS


class ConfigurationParsingTest(unittest.TestCase):

    def setUp(self):
        self.maxDiff = None

    def test_use_defaults_on_failure(self):
        config = _load_config('this file will never exist')
        expected = CONFIG_DEFAULTS
        self.assertEquals(expected, config)

    def test_security_values_configuration(self):
        # given
        config_path = resource_filename('test_soledad',
                                        'fixture_soledad.conf')
        # when
        config = _load_config(config_path)

        # then
        expected = {'members': ['user1', 'user2'],
                    'members_roles': ['role1', 'role2'],
                    'admins': ['user3', 'user4'],
                    'admins_roles': ['role3', 'role3']}
        self.assertDictEqual(expected, config['database-security'])

    def test_server_values_configuration(self):
        # given
        config_path = resource_filename('test_soledad',
                                        'fixture_soledad.conf')
        # when
        config = _load_config(config_path)

        # then
        expected = {'couch_url':
                    'http://soledad:passwd@localhost:5984',
                    'create_cmd':
                    'sudo -u soledad-admin /usr/bin/create-user-db',
                    'admin_netrc':
                    '/etc/couchdb/couchdb-soledad-admin.netrc',
                    'batching': False,
                    'blobs': False}
        self.assertDictEqual(expected, config['soledad-server'])
