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


from mock import Mock
from leap.common.testing.basetest import BaseLeapTest
from leap.soledad.tests import BaseSoledadTest
from leap.soledad import Soledad
from leap.soledad.crypto import SoledadCrypto
from leap.soledad.shared_db import SoledadSharedDatabase
from leap.soledad.backends.leap_backend import LeapDocument


class AuxMethodsTestCase(BaseSoledadTest):

    def test__init_dirs(self):
        sol = self._soledad_instance(prefix='/_init_dirs')
        sol._init_dirs()
        local_db_dir = os.path.dirname(sol._config.get_local_db_path())
        secret_path = os.path.dirname(sol._config.get_secret_path())
        self.assertTrue(os.path.isdir(local_db_dir))
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
            "secret_path": "value_1",
            "local_db_path": "value_2",
            "shared_db_url": "value_3"
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
        self.assertEqual('value_1', sol._config.get_secret_path())
        self.assertEqual('value_2', sol._config.get_local_db_path())
        self.assertEqual('value_3', sol._config.get_shared_db_url())

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
            secret_path='value_3',
            local_db_path='value_2',
            shared_db_url='value_1')
        self.assertEqual('value_3', sol._config.get_secret_path())
        self.assertEqual('value_2', sol._config.get_local_db_path())
        self.assertEqual('value_1', sol._config.get_shared_db_url())


class SoledadSharedDBTestCase(BaseSoledadTest):
    """
    These tests ensure the functionalities of the shared recovery database.
    """

    def setUp(self):
        BaseSoledadTest.setUp(self)
        self._shared_db = SoledadSharedDatabase(
            'https://provider/', LeapDocument, None)

    def test__fetch_keys_from_shared_db(self):
        """
        Ensure the shared db is queried with the correct doc_id.
        """
        self._soledad._shared_db = Mock()
        doc_id = self._soledad._address_hash()
        self._soledad._fetch_keys_from_shared_db()
        self.assertTrue(
            self._soledad._shared_db.get_doc_unauth.assert_called_once(doc_id),
            'Wrong doc_id when fetching recovery document.')

    def test__assert_keys_in_shared_db(self):
        """
        Ensure recovery document is put into shared recover db.
        """

        def _put_doc_side_effect(doc):
            self._doc_put = doc

        class MockSharedDB(object):

            get_doc_unauth = Mock(return_value=None)
            put_doc = Mock(side_effect=_put_doc_side_effect)

            def __call__(self):
                return self

        self._soledad._shared_db = MockSharedDB()
        doc_id = self._soledad._address_hash()
        self._soledad._assert_keys_in_shared_db()
        self.assertTrue(
            self._soledad._shared_db().get_doc_unauth.assert_called_once_with(
                doc_id) is None,
            'Wrong doc_id when fetching recovery document.')
        self.assertTrue(
            self._soledad._shared_db.put_doc.assert_called_once_with(
                self._doc_put) is None,
            'Wrong document when putting recovery document.')
        self.assertTrue(
            self._doc_put.doc_id == doc_id,
            'Wrong doc_id when putting recovery document.')
