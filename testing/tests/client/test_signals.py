from mock import Mock
from twisted.internet import defer

from leap import soledad
from leap.common.events import catalog
from leap.soledad.common.document import SoledadDocument

from test_soledad.util import ADDRESS
from test_soledad.util import BaseSoledadTest


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
            local_db_path='alternative_stage3.u1db')
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
