# -*- coding: utf-8 -*-
# test_soledad.py
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
Tests for general Soledad functionality.
"""


import os
import re
import tempfile
try:
    import simplejson as json
except ImportError:
    import json  # noqa


from leap.soledad.tests import BaseSoledadTest
from leap.soledad import Soledad
from leap.soledad.crypto import SoledadCrypto


class AuxMethodsTestCase(BaseSoledadTest):

    def test__init_dirs(self):
        sol = self._soledad_instance(prefix='/_init_dirs')
        sol._init_dirs()
        local_db_dir = os.path.dirname(sol._config.get_local_db_path())
        gnupg_home = os.path.dirname(sol._config.get_gnupg_home())
        secret_path = os.path.dirname(sol._config.get_secret_path())
        self.assertTrue(os.path.isdir(local_db_dir))
        self.assertTrue(os.path.isdir(gnupg_home))
        self.assertTrue(os.path.isdir(secret_path))

    def test__init_db(self):
        sol = self._soledad_instance()
        sol._init_dirs()
        sol._crypto = SoledadCrypto(sol)
        #self._soledad._gpg.import_keys(PUBLIC_KEY)
        if not sol._has_symkey():
            sol._gen_symkey()
        sol._load_symkey()
        sol._init_db()
        from leap.soledad.backends.sqlcipher import SQLCipherDatabase
        self.assertIsInstance(sol._db, SQLCipherDatabase)

    def test__init_config_default(self):
        """
        Test if configuration defaults point to the correct place.
        """
        sol = Soledad('leap@leap.se', passphrase='123', bootstrap=False)
        self.assertTrue(bool(re.match(
            '.*/\.config/leap/soledad/gnupg', sol._config.get_gnupg_home())))
        self.assertTrue(bool(re.match(
            '.*/\.config/leap/soledad/secret.gpg',
            sol._config.get_secret_path())))
        self.assertTrue(bool(re.match(
            '.*/\.config/leap/soledad/soledad.u1db',
            sol._config.get_local_db_path())))
        self.assertEqual(
            'http://provider/soledad/shared',
            sol._config.get_shared_db_url())

    def test__init_config_defaults(self):
        """
        Test if configuration defaults point to the correct place.
        """
        # we use regexp match here because HOME environment variable is
        # changed by the BaseLeapTest class but BaseConfig does not capture
        # that change.
        sol = Soledad('leap@leap.se', passphrase='123', bootstrap=False)
        self.assertTrue(bool(re.match(
            '.*/\.config/leap/soledad/gnupg', sol._config.get_gnupg_home())))
        self.assertTrue(bool(re.match(
            '.*/\.config/leap/soledad/secret.gpg',
            sol._config.get_secret_path())))
        self.assertTrue(bool(re.match(
            '.*/\.config/leap/soledad/soledad.u1db',
            sol._config.get_local_db_path())))
        self.assertEqual(
            'http://provider/soledad/shared',
            sol._config.get_shared_db_url())

    def test__init_config_from_file(self):
        """
        Test if configuration is correctly read from file.
        """
        # we use regexp match here because HOME environment variable is
        # changed by the BaseLeapTest class but BaseConfig does not capture
        # that change.
        config_values = {
            "gnupg_home": "value_1",
            "secret_path": "value_2",
            "local_db_path": "value_3",
            "shared_db_url": "value_4"
        }
        tmpfile = tempfile.mktemp(dir=self.tempdir)
        f = open(tmpfile, 'w')
        f.write(json.dumps(config_values))
        f.close()
        sol = Soledad(
            'leap@leap.se',
            passphrase='123',
            bootstrap=False,
            config_path=tmpfile)
        self.assertEqual('value_1', sol._config.get_gnupg_home())
        self.assertEqual('value_2', sol._config.get_secret_path())
        self.assertEqual('value_3', sol._config.get_local_db_path())
        self.assertEqual('value_4', sol._config.get_shared_db_url())

    def test__init_config_from_params(self):
        """
        Test if configuration is correctly read from file.
        """
        # we use regexp match here because HOME environment variable is
        # changed by the BaseLeapTest class but BaseConfig does not capture
        # that change.
        sol = Soledad(
            'leap@leap.se',
            passphrase='123',
            bootstrap=False,
            gnupg_home='value_4',
            secret_path='value_3',
            local_db_path='value_2',
            shared_db_url='value_1')
        self.assertEqual('value_4', sol._config.get_gnupg_home())
        self.assertEqual('value_3', sol._config.get_secret_path())
        self.assertEqual('value_2', sol._config.get_local_db_path())
        self.assertEqual('value_1', sol._config.get_shared_db_url())
