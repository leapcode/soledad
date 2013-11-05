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


from pysqlcipher.dbapi2 import DatabaseError
from leap.common.events import events_pb2 as proto
from leap.soledad.common.tests import (
    BaseSoledadTest,
    ADDRESS,
)
from leap import soledad
from leap.soledad.common.document import SoledadDocument
from leap.soledad.client import Soledad, PassphraseTooShort
from leap.soledad.client.crypto import SoledadCrypto
from leap.soledad.client.shared_db import SoledadSharedDatabase
from leap.soledad.client.target import SoledadSyncTarget


class AuxMethodsTestCase(BaseSoledadTest):

    def test__init_dirs(self):
        sol = self._soledad_instance(prefix='_init_dirs')
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
        from leap.soledad.client.sqlcipher import SQLCipherDatabase
        self.assertIsInstance(sol._db, SQLCipherDatabase)

    def test__init_config_defaults(self):
        """
        Test if configuration defaults point to the correct place.
        """

        class SoledadMock(Soledad):

            def __init__(self):
                pass

        # instantiate without initializing so we just test _init_config()
        sol = SoledadMock()
        Soledad._init_config(sol, None, None, '')
        # assert value of secrets_path
        self.assertEquals(
            os.path.join(
                sol.DEFAULT_PREFIX, Soledad.STORAGE_SECRETS_FILE_NAME),
            sol.secrets_path)
        # assert value of local_db_path
        self.assertEquals(
            os.path.join(sol.DEFAULT_PREFIX, 'soledad.u1db'),
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
            sol.secrets_path)
        self.assertEqual(
            os.path.join(self.tempdir, 'value_2'),
            sol.local_db_path)
        self.assertEqual('value_1', sol.server_url)

    def test_change_passphrase(self):
        """
        Test if passphrase can be changed.
        """
        sol = self._soledad_instance(
            'leap@leap.se',
            passphrase=u'123',
            prefix=self.rand_prefix,
        )
        doc = sol.create_doc({'simple': 'doc'})
        doc_id = doc.doc_id

        # change the passphrase
        sol.change_passphrase(u'654321')

        self.assertRaises(
            DatabaseError,
            self._soledad_instance, 'leap@leap.se',
            passphrase=u'123',
            prefix=self.rand_prefix)

        # use new passphrase and retrieve doc
        sol2 = self._soledad_instance(
            'leap@leap.se',
            passphrase=u'654321',
            prefix=self.rand_prefix)
        doc2 = sol2.get_doc(doc_id)
        self.assertEqual(doc, doc2)

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

    def test_get_passphrase(self):
        """
        Assert passphrase getter works fine.
        """
        sol = self._soledad_instance()
        self.assertEqual('123', sol.passphrase)


class SoledadSharedDBTestCase(BaseSoledadTest):
    """
    These tests ensure the functionalities of the shared recovery database.
    """

    def setUp(self):
        BaseSoledadTest.setUp(self)
        self._shared_db = SoledadSharedDatabase(
            'https://provider/', ADDRESS, document_factory=SoledadDocument,
            creds=None)

    def test__get_secrets_from_shared_db(self):
        """
        Ensure the shared db is queried with the correct doc_id.
        """
        doc_id = self._soledad._shared_db_doc_id()
        self._soledad._get_secrets_from_shared_db()
        self.assertTrue(
            self._soledad._shared_db().get_doc.assert_called_with(
                doc_id) is None,
            'Wrong doc_id when fetching recovery document.')

    def test__put_secrets_in_shared_db(self):
        """
        Ensure recovery document is put into shared recover db.
        """
        doc_id = self._soledad._shared_db_doc_id()
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


class SoledadSignalingTestCase(BaseSoledadTest):
    """
    These tests ensure signals are correctly emmited by Soledad.
    """

    EVENTS_SERVER_PORT = 8090

    def setUp(self):
        # mock signaling
        soledad.client.signal = Mock()
        # run parent's setUp
        BaseSoledadTest.setUp(self)

    def tearDown(self):
        pass

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
        soledad.client.signal.reset_mock()
        # get a fresh instance so it emits all bootstrap signals
        sol = self._soledad_instance(
            secrets_path='alternative_stage3.json',
            local_db_path='alternative_stage3.u1db')
        # reverse call order so we can verify in the order the signals were
        # expected
        soledad.client.signal.mock_calls.reverse()
        soledad.client.signal.call_args = \
            soledad.client.signal.call_args_list[0]
        soledad.client.signal.call_args_list.reverse()
        # downloading keys signals
        soledad.client.signal.assert_called_with(
            proto.SOLEDAD_DOWNLOADING_KEYS,
            ADDRESS,
        )
        self._pop_mock_call(soledad.client.signal)
        soledad.client.signal.assert_called_with(
            proto.SOLEDAD_DONE_DOWNLOADING_KEYS,
            ADDRESS,
        )
        # creating keys signals
        self._pop_mock_call(soledad.client.signal)
        soledad.client.signal.assert_called_with(
            proto.SOLEDAD_CREATING_KEYS,
            ADDRESS,
        )
        self._pop_mock_call(soledad.client.signal)
        soledad.client.signal.assert_called_with(
            proto.SOLEDAD_DONE_CREATING_KEYS,
            ADDRESS,
        )
        # downloading once more (inside _put_keys_in_shared_db)
        self._pop_mock_call(soledad.client.signal)
        soledad.client.signal.assert_called_with(
            proto.SOLEDAD_DOWNLOADING_KEYS,
            ADDRESS,
        )
        self._pop_mock_call(soledad.client.signal)
        soledad.client.signal.assert_called_with(
            proto.SOLEDAD_DONE_DOWNLOADING_KEYS,
            ADDRESS,
        )
        # uploading keys signals
        self._pop_mock_call(soledad.client.signal)
        soledad.client.signal.assert_called_with(
            proto.SOLEDAD_UPLOADING_KEYS,
            ADDRESS,
        )
        self._pop_mock_call(soledad.client.signal)
        soledad.client.signal.assert_called_with(
            proto.SOLEDAD_DONE_UPLOADING_KEYS,
            ADDRESS,
        )
        # assert db was locked and unlocked
        sol._shared_db.lock.assert_called_with()
        sol._shared_db.unlock.assert_called_with('atoken')

    def test_stage2_bootstrap_signals(self):
        """
        Test that if there are keys in server, soledad will download them and
        emit corresponding signals.
        """
        # get existing instance so we have access to keys
        sol = self._soledad_instance()
        # create a document with secrets
        doc = SoledadDocument(doc_id=sol._shared_db_doc_id())
        doc.content = sol.export_recovery_document(include_uuid=False)

        class Stage2MockSharedDB(object):

            get_doc = Mock(return_value=doc)
            put_doc = Mock()
            lock = Mock(return_value=('atoken', 300))
            unlock = Mock()

            def __call__(self):
                return self

        # reset mock
        soledad.client.signal.reset_mock()
        # get a fresh instance so it emits all bootstrap signals
        sol = self._soledad_instance(
            secrets_path='alternative_stage2.json',
            local_db_path='alternative_stage2.u1db',
            shared_db_class=Stage2MockSharedDB)
        # reverse call order so we can verify in the order the signals were
        # expected
        soledad.client.signal.mock_calls.reverse()
        soledad.client.signal.call_args = \
            soledad.client.signal.call_args_list[0]
        soledad.client.signal.call_args_list.reverse()
        # assert download keys signals
        soledad.client.signal.assert_called_with(
            proto.SOLEDAD_DOWNLOADING_KEYS,
            ADDRESS,
        )
        self._pop_mock_call(soledad.client.signal)
        soledad.client.signal.assert_called_with(
            proto.SOLEDAD_DONE_DOWNLOADING_KEYS,
            ADDRESS,
        )

    def test_stage1_bootstrap_signals(self):
        """
        Test that if soledad already has a local secret, it emits no signals.
        """
        soledad.client.signal.reset_mock()
        # get an existent instance so it emits only some of bootstrap signals
        sol = self._soledad_instance()
        self.assertEqual([], soledad.client.signal.mock_calls)

    def test_sync_signals(self):
        """
        Test Soledad emits SOLEDAD_CREATING_KEYS signal.
        """
        soledad.client.signal.reset_mock()
        # get a fresh instance so it emits all bootstrap signals
        sol = self._soledad_instance()
        # mock the actual db sync so soledad does not try to connect to the
        # server
        sol._db.sync = Mock()
        # do the sync
        sol.sync()
        # assert the signal has been emitted
        soledad.client.signal.assert_called_with(
            proto.SOLEDAD_DONE_DATA_SYNC,
            ADDRESS,
        )

    def test_need_sync_signals(self):
        """
        Test Soledad emits SOLEDAD_CREATING_KEYS signal.
        """
        soledad.client.signal.reset_mock()
        sol = self._soledad_instance()
        # mock the sync target
        old_get_sync_info = SoledadSyncTarget.get_sync_info
        SoledadSyncTarget.get_sync_info = Mock(return_value=[0, 0, 0, 0, 2])
        # mock our generation so soledad thinks there's new data to sync
        sol._db._get_generation = Mock(return_value=1)
        # check for new data to sync
        sol.need_sync('http://provider/userdb')
        # assert the signal has been emitted
        soledad.client.signal.assert_called_with(
            proto.SOLEDAD_NEW_DATA_TO_SYNC,
            ADDRESS,
        )
        SoledadSyncTarget.get_sync_info = old_get_sync_info
