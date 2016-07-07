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

from twisted.internet import defer

from leap.soledad.common.errors import DatabaseAccessError
from leap.soledad.client import Soledad
from leap.soledad.client.adbapi import U1DBConnectionPool
from leap.soledad.client.secrets import PassphraseTooShort

from test_soledad.util import BaseSoledadTest


class AuxMethodsTestCase(BaseSoledadTest):

    def test__init_dirs(self):
        sol = self._soledad_instance(prefix='_init_dirs')
        local_db_dir = os.path.dirname(sol.local_db_path)
        secrets_path = os.path.dirname(sol.secrets.secrets_path)
        self.assertTrue(os.path.isdir(local_db_dir))
        self.assertTrue(os.path.isdir(secrets_path))

        def _close_soledad(results):
            sol.close()

        d = sol.create_doc({})
        d.addCallback(_close_soledad)
        return d

    def test__init_u1db_sqlcipher_backend(self):
        sol = self._soledad_instance(prefix='_init_db')
        self.assertIsInstance(sol._dbpool, U1DBConnectionPool)
        self.assertTrue(os.path.isfile(sol.local_db_path))
        sol.close()

    def test__init_config_with_defaults(self):
        """
        Test if configuration defaults point to the correct place.
        """

        class SoledadMock(Soledad):

            def __init__(self):
                pass

        # instantiate without initializing so we just test
        # _init_config_with_defaults()
        sol = SoledadMock()
        sol._passphrase = u''
        sol._server_url = ''
        sol._init_config_with_defaults()
        # assert value of local_db_path
        self.assertEquals(
            os.path.join(sol.default_prefix, 'soledad.u1db'),
            sol.local_db_path)

    def test__init_config_from_params(self):
        """
        Test if configuration is correctly read from file.
        """
        sol = self._soledad_instance(
            'leap@leap.se',
            passphrase=u'123',
            secrets_path='value_3',
            local_db_path='value_2',
            server_url='value_1',
            cert_file=None)
        self.assertEqual(
            os.path.join(self.tempdir, 'value_3'),
            sol.secrets.secrets_path)
        self.assertEqual(
            os.path.join(self.tempdir, 'value_2'),
            sol.local_db_path)
        self.assertEqual('value_1', sol._server_url)
        sol.close()

    @defer.inlineCallbacks
    def test_change_passphrase(self):
        """
        Test if passphrase can be changed.
        """
        prefix = '_change_passphrase'
        sol = self._soledad_instance(
            'leap@leap.se',
            passphrase=u'123',
            prefix=prefix,
        )

        doc1 = yield sol.create_doc({'simple': 'doc'})
        sol.change_passphrase(u'654321')
        sol.close()

        with self.assertRaises(DatabaseAccessError):
            self._soledad_instance(
                'leap@leap.se',
                passphrase=u'123',
                prefix=prefix)

        sol2 = self._soledad_instance(
            'leap@leap.se',
            passphrase=u'654321',
            prefix=prefix)
        doc2 = yield sol2.get_doc(doc1.doc_id)

        self.assertEqual(doc1, doc2)

        sol2.close()

    def test_change_passphrase_with_short_passphrase_raises(self):
        """
        Test if attempt to change passphrase passing a short passphrase
        raises.
        """
        sol = self._soledad_instance(
            'leap@leap.se',
            passphrase=u'123')
        # check that soledad complains about new passphrase length
        self.assertRaises(
            PassphraseTooShort,
            sol.change_passphrase, u'54321')
        sol.close()

    def test_get_passphrase(self):
        """
        Assert passphrase getter works fine.
        """
        sol = self._soledad_instance()
        self.assertEqual('123', sol._passphrase)
        sol.close()
