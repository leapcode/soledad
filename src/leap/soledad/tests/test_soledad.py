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
        local_db_dir = os.path.dirname(sol.local_db_path)
        secrets_path = os.path.dirname(sol.secrets_path)
        self.assertTrue(os.path.isdir(local_db_dir))
        self.assertTrue(os.path.isdir(secrets_path))

    def test__init_db(self):
        sol = self._soledad_instance()
        sol._init_dirs()
        sol._crypto = SoledadCrypto(sol)
        #self._soledad._gpg.import_keys(PUBLIC_KEY)
        if not sol._has_secret():
            sol._gen_secret()
        sol._load_secrets()
        sol._init_db()
        from leap.soledad.backends.sqlcipher import SQLCipherDatabase
        self.assertIsInstance(sol._db, SQLCipherDatabase)

    def test__init_config_defaults(self):
        """
        Test if configuration defaults point to the correct place.
        """
        sol = Soledad(
            'leap@leap.se', passphrase='123',
            secrets_path=None, local_db_path=None,
            server_url='', cert_file=None)  # otherwise Soledad will fail.
        self.assertEquals(
            os.path.join(sol.DEFAULT_PREFIX, Soledad.STORAGE_SECRETS_FILE_NAME),
            sol.secrets_path)
        self.assertEquals(
            os.path.join(sol.DEFAULT_PREFIX, 'soledad.u1db'),
            sol.local_db_path)

    def test__init_config_from_params(self):
        """
        Test if configuration is correctly read from file.
        """
        sol = self._soledad_instance(
            'leap@leap.se',
            passphrase='123',
            secrets_path='value_3',
            local_db_path='value_2',
            server_url='value_1',
            cert_file=None)
        self.assertEqual(self.tempdir+'value_3', sol.secrets_path)
        self.assertEqual(self.tempdir+'value_2', sol.local_db_path)
        self.assertEqual('value_1', sol.server_url)


class SoledadSharedDBTestCase(BaseSoledadTest):
    """
    These tests ensure the functionalities of the shared recovery database.
    """

    def setUp(self):
        BaseSoledadTest.setUp(self)
        self._shared_db = SoledadSharedDatabase(
            'https://provider/', LeapDocument, None)

    def test__get_secrets_from_shared_db(self):
        """
        Ensure the shared db is queried with the correct doc_id.
        """
        doc_id = self._soledad._uuid_hash()
        self._soledad._get_secrets_from_shared_db()
        self.assertTrue(
            self._soledad._shared_db().get_doc.assert_called_with(
                doc_id) is None,
            'Wrong doc_id when fetching recovery document.')

    def test__put_secrets_in_shared_db(self):
        """
        Ensure recovery document is put into shared recover db.
        """
        doc_id = self._soledad._uuid_hash()
        self._soledad._put_secrets_in_shared_db()
        self.assertTrue(
            self._soledad._shared_db().get_doc.assert_called_with(
                doc_id) is None,
            'Wrong doc_id when fetching recovery document.')
        self.assertTrue(
            self._soledad._shared_db.put_doc.assert_called_with(
                self._doc_put) is None,
            'Wrong document when putting recovery document.')
        self.assertTrue(
            self._doc_put.doc_id == doc_id,
            'Wrong doc_id when putting recovery document.')
