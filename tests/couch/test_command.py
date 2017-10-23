from twisted.trial import unittest

from leap.soledad.common.couch import state as couch_state
from leap.soledad.common.l2db import errors as u1db_errors

from mock import Mock


class CommandBasedDBCreationTest(unittest.TestCase):

    def test_ensure_db_using_custom_command(self):
        state = couch_state.CouchServerState(
            "url", create_cmd="/bin/echo", check_schema_versions=False)
        mock_db = Mock()
        mock_db.replica_uid = 'replica_uid'
        state.open_database = Mock(return_value=mock_db)
        db, replica_uid = state.ensure_database("user-1337")  # works
        self.assertEquals(mock_db, db)
        self.assertEquals(mock_db.replica_uid, replica_uid)

    def test_raises_unauthorized_on_failure(self):
        state = couch_state.CouchServerState(
            "url", create_cmd="inexistent", check_schema_versions=False)
        self.assertRaises(u1db_errors.Unauthorized,
                          state.ensure_database, "user-1337")

    def test_raises_unauthorized_by_default(self):
        state = couch_state.CouchServerState("url",
                                             check_schema_versions=False)
        self.assertRaises(u1db_errors.Unauthorized,
                          state.ensure_database, "user-1337")
