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

from mock import Mock

from twisted.internet import defer

from leap.common.events import catalog
from leap.soledad.common.tests.util import (
    BaseSoledadTest,
    ADDRESS,
)
from leap import soledad
from leap.soledad.common.document import SoledadDocument
from leap.soledad.common.errors import DatabaseAccessError
from leap.soledad.client import Soledad
from leap.soledad.client.adbapi import U1DBConnectionPool
from leap.soledad.client.secrets import PassphraseTooShort
from leap.soledad.client.shared_db import SoledadSharedDatabase


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

        def _change_passphrase(doc1):
            self._doc1 = doc1
            sol.change_passphrase(u'654321')
            sol.close()

        def _assert_wrong_password_raises(results):
            with self.assertRaises(DatabaseAccessError):
                self._soledad_instance(
                    'leap@leap.se',
                    passphrase=u'123',
                    prefix=prefix)

        def _instantiate_with_new_passphrase(results):
            sol2 = self._soledad_instance(
                'leap@leap.se',
                passphrase=u'654321',
                prefix=prefix)
            self._sol2 = sol2
            return sol2.get_doc(self._doc1.doc_id)

        def _assert_docs_are_equal(doc2):
            self.assertEqual(self._doc1, doc2)
            self._sol2.close()

        d = sol.create_doc({'simple': 'doc'})
        d.addCallback(_change_passphrase)
        d.addCallback(_assert_wrong_password_raises)
        d.addCallback(_instantiate_with_new_passphrase)
        d.addCallback(_assert_docs_are_equal)
        d.addCallback(lambda _: sol.close())

        return d

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


class SoledadSharedDBTestCase(BaseSoledadTest):

    """
    These tests ensure the functionalities of the shared recovery database.
    """

    def setUp(self):
        BaseSoledadTest.setUp(self)
        self._shared_db = SoledadSharedDatabase(
            'https://provider/', ADDRESS, document_factory=SoledadDocument,
            creds=None)

    def tearDown(self):
        BaseSoledadTest.tearDown(self)

    def test__get_secrets_from_shared_db(self):
        """
        Ensure the shared db is queried with the correct doc_id.
        """
        doc_id = self._soledad.secrets._shared_db_doc_id()
        self._soledad.secrets._get_secrets_from_shared_db()
        self.assertTrue(
            self._soledad.shared_db.get_doc.assert_called_with(
                doc_id) is None,
            'Wrong doc_id when fetching recovery document.')

    def test__put_secrets_in_shared_db(self):
        """
        Ensure recovery document is put into shared recover db.
        """
        doc_id = self._soledad.secrets._shared_db_doc_id()
        self._soledad.secrets._put_secrets_in_shared_db()
        self.assertTrue(
            self._soledad.shared_db.get_doc.assert_called_with(
                doc_id) is None,
            'Wrong doc_id when fetching recovery document.')
        self.assertTrue(
            self._soledad.shared_db.put_doc.assert_called_with(
                self._doc_put) is None,
            'Wrong document when putting recovery document.')
        self.assertTrue(
            self._doc_put.doc_id == doc_id,
            'Wrong doc_id when putting recovery document.')


class SoledadSignalingTestCase(BaseSoledadTest):

    """
    These tests ensure signals are correctly emmited by Soledad.
    """

    EVENTS_SERVER_PORT = 8090

    def setUp(self):
        # mock signaling
        soledad.client.signal = Mock()
        soledad.client.secrets.events.emit_async = Mock()
        # run parent's setUp
        BaseSoledadTest.setUp(self)

    def tearDown(self):
        BaseSoledadTest.tearDown(self)

    def _pop_mock_call(self, mocked):
        mocked.call_args_list.pop()
        mocked.mock_calls.pop()
        mocked.call_args = mocked.call_args_list[-1]

    def test_stage3_bootstrap_signals(self):
        """
        Test that a fresh soledad emits all bootstrap signals.

        Signals are:
          - downloading keys / done downloading keys.
          - creating keys / done creating keys.
          - downloading keys / done downloading keys.
          - uploading keys / done uploading keys.
        """
        soledad.client.secrets.events.emit_async.reset_mock()
        # get a fresh instance so it emits all bootstrap signals
        sol = self._soledad_instance(
            secrets_path='alternative_stage3.json',
            local_db_path='alternative_stage3.u1db',
            userid=ADDRESS)
        # reverse call order so we can verify in the order the signals were
        # expected
        soledad.client.secrets.events.emit_async.mock_calls.reverse()
        soledad.client.secrets.events.emit_async.call_args = \
            soledad.client.secrets.events.emit_async.call_args_list[0]
        soledad.client.secrets.events.emit_async.call_args_list.reverse()

        user_data = {'userid': ADDRESS, 'uuid': ADDRESS}

        # downloading keys signals
        soledad.client.secrets.events.emit_async.assert_called_with(
            catalog.SOLEDAD_DOWNLOADING_KEYS, user_data
        )
        self._pop_mock_call(soledad.client.secrets.events.emit_async)
        soledad.client.secrets.events.emit_async.assert_called_with(
            catalog.SOLEDAD_DONE_DOWNLOADING_KEYS, user_data
        )
        # creating keys signals
        self._pop_mock_call(soledad.client.secrets.events.emit_async)
        soledad.client.secrets.events.emit_async.assert_called_with(
            catalog.SOLEDAD_CREATING_KEYS, user_data
        )
        self._pop_mock_call(soledad.client.secrets.events.emit_async)
        soledad.client.secrets.events.emit_async.assert_called_with(
            catalog.SOLEDAD_DONE_CREATING_KEYS, user_data
        )
        # downloading once more (inside _put_keys_in_shared_db)
        self._pop_mock_call(soledad.client.secrets.events.emit_async)
        soledad.client.secrets.events.emit_async.assert_called_with(
            catalog.SOLEDAD_DOWNLOADING_KEYS, user_data
        )
        self._pop_mock_call(soledad.client.secrets.events.emit_async)
        soledad.client.secrets.events.emit_async.assert_called_with(
            catalog.SOLEDAD_DONE_DOWNLOADING_KEYS, user_data
        )
        # uploading keys signals
        self._pop_mock_call(soledad.client.secrets.events.emit_async)
        soledad.client.secrets.events.emit_async.assert_called_with(
            catalog.SOLEDAD_UPLOADING_KEYS, user_data
        )
        self._pop_mock_call(soledad.client.secrets.events.emit_async)
        soledad.client.secrets.events.emit_async.assert_called_with(
            catalog.SOLEDAD_DONE_UPLOADING_KEYS, user_data
        )
        # assert db was locked and unlocked
        sol.shared_db.lock.assert_called_with()
        sol.shared_db.unlock.assert_called_with('atoken')
        sol.close()

    def test_stage2_bootstrap_signals(self):
        """
        Test that if there are keys in server, soledad will download them and
        emit corresponding signals.
        """
        # get existing instance so we have access to keys
        sol = self._soledad_instance()
        # create a document with secrets
        doc = SoledadDocument(doc_id=sol.secrets._shared_db_doc_id())
        doc.content = sol.secrets._export_recovery_document()
        sol.close()
        # reset mock
        soledad.client.secrets.events.emit_async.reset_mock()
        # get a fresh instance so it emits all bootstrap signals
        shared_db = self.get_default_shared_mock(get_doc_return_value=doc)
        sol = self._soledad_instance(
            secrets_path='alternative_stage2.json',
            local_db_path='alternative_stage2.u1db',
            shared_db_class=shared_db)
        # reverse call order so we can verify in the order the signals were
        # expected
        soledad.client.secrets.events.emit_async.mock_calls.reverse()
        soledad.client.secrets.events.emit_async.call_args = \
            soledad.client.secrets.events.emit_async.call_args_list[0]
        soledad.client.secrets.events.emit_async.call_args_list.reverse()
        # assert download keys signals
        soledad.client.secrets.events.emit_async.assert_called_with(
            catalog.SOLEDAD_DOWNLOADING_KEYS,
            {'userid': ADDRESS, 'uuid': ADDRESS}
        )
        self._pop_mock_call(soledad.client.secrets.events.emit_async)
        soledad.client.secrets.events.emit_async.assert_called_with(
            catalog.SOLEDAD_DONE_DOWNLOADING_KEYS,
            {'userid': ADDRESS, 'uuid': ADDRESS},
        )
        sol.close()

    def test_stage1_bootstrap_signals(self):
        """
        Test that if soledad already has a local secret, it emits no signals.
        """
        soledad.client.signal.reset_mock()
        # get an existent instance so it emits only some of bootstrap signals
        sol = self._soledad_instance()
        self.assertEqual([], soledad.client.signal.mock_calls)
        sol.close()

    @defer.inlineCallbacks
    def test_sync_signals(self):
        """
        Test Soledad emits SOLEDAD_CREATING_KEYS signal.
        """
        # get a fresh instance so it emits all bootstrap signals
        sol = self._soledad_instance()
        soledad.client.signal.reset_mock()

        # mock the actual db sync so soledad does not try to connect to the
        # server
        d = defer.Deferred()
        d.callback(None)
        sol._dbsyncer.sync = Mock(return_value=d)

        yield sol.sync()

        # assert the signal has been emitted
        soledad.client.events.emit_async.assert_called_with(
            catalog.SOLEDAD_DONE_DATA_SYNC,
            {'userid': ADDRESS, 'uuid': ADDRESS},
        )
        sol.close()
