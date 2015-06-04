# test_sync_deferred.py
# Copyright (C) 2014 LEAP
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
Test Leap backend bits: sync with deferred encryption/decryption.
"""
import time
import os
import random
import string
import shutil

from urlparse import urljoin

from leap.soledad.common import couch
from leap.soledad.client.sqlcipher import (
    SQLCipherOptions,
    SQLCipherDatabase,
    SQLCipherU1DBSync,
)

from testscenarios import TestWithScenarios

from leap.soledad.common.tests import u1db_tests as tests
from leap.soledad.common.tests.u1db_tests import test_sync
from leap.soledad.common.tests.util import ADDRESS
from leap.soledad.common.tests.util import SoledadWithCouchServerMixin
from leap.soledad.common.tests.util import make_soledad_app


# Just to make clear how this test is different... :)
DEFER_DECRYPTION = True

WAIT_STEP = 1
MAX_WAIT = 10
DBPASS = "pass"


class BaseSoledadDeferredEncTest(SoledadWithCouchServerMixin):
    """
    Another base class for testing the deferred encryption/decryption during
    the syncs, using the intermediate database.
    """
    defer_sync_encryption = True

    def setUp(self):
        SoledadWithCouchServerMixin.setUp(self)
        # config info
        self.db1_file = os.path.join(self.tempdir, "db1.u1db")
        os.unlink(self.db1_file)
        self.db_pass = DBPASS
        self.email = ADDRESS

        # get a random prefix for each test, so we do not mess with
        # concurrency during initialization and shutting down of
        # each local db.
        self.rand_prefix = ''.join(
            map(lambda x: random.choice(string.ascii_letters), range(6)))

        # open test dbs: db1 will be the local sqlcipher db (which
        # instantiates a syncdb). We use the self._soledad instance that was
        # already created on some setUp method.
        import binascii
        tohex = binascii.b2a_hex
        key = tohex(self._soledad.secrets.get_local_storage_key())
        sync_db_key = tohex(self._soledad.secrets.get_sync_db_key())
        dbpath = self._soledad._local_db_path

        self.opts = SQLCipherOptions(
            dbpath, key, is_raw_key=True, create=False,
            defer_encryption=True, sync_db_key=sync_db_key)
        self.db1 = SQLCipherDatabase(self.opts)

        self.db2 = couch.CouchDatabase.open_database(
            urljoin(
                'http://localhost:' + str(self.wrapper.port), 'test'),
                create=True,
                ensure_ddocs=True)

    def tearDown(self):
        self.db1.close()
        self.db2.close()
        self._soledad.close()

        # XXX should not access "private" attrs
        shutil.rmtree(os.path.dirname(self._soledad._local_db_path))
        SoledadWithCouchServerMixin.tearDown(self)


class SyncTimeoutError(Exception):
    """
    Dummy exception to notify timeout during sync.
    """
    pass


class TestSoledadDbSyncDeferredEncDecr(
        TestWithScenarios,
        test_sync.TestDbSync,
        BaseSoledadDeferredEncTest):
    """
    Test db.sync remote sync shortcut.
    Case with deferred encryption and decryption: using the intermediate
    syncdb.
    """

    scenarios = [
        ('http', {
            'make_app_with_state': make_soledad_app,
            'make_database_for_test': tests.make_memory_database_for_test,
        }),
    ]

    oauth = False
    token = True

    def make_app(self):
        self.request_state = couch.CouchServerState(self._couch_url)
        return self.make_app_with_state(self.request_state)

    def setUp(self):
        """
        Need to explicitely invoke inicialization on all bases.
        """
        BaseSoledadDeferredEncTest.setUp(self)
        self.server = self.server_thread = None
        self.startServer()
        self.syncer = None

    def tearDown(self):
        """
        Need to explicitely invoke destruction on all bases.
        """
        dbsyncer = getattr(self, 'dbsyncer', None)
        if dbsyncer:
            dbsyncer.close()
        BaseSoledadDeferredEncTest.tearDown(self)

    def do_sync(self, target_name):
        """
        Perform sync using SoledadSynchronizer, SoledadSyncTarget
        and Token auth.
        """
        if self.token:
            creds={'token': {
                'uuid': 'user-uuid',
                'token': 'auth-token',
            }}
            target_url = self.getURL(target_name)

            # get a u1db syncer
            crypto = self._soledad._crypto
            replica_uid = self.db1._replica_uid
            dbsyncer = SQLCipherU1DBSync(self.opts, crypto, replica_uid,
                defer_encryption=True)
            self.dbsyncer = dbsyncer
            return dbsyncer.sync(target_url, creds=creds,
                autocreate=True,defer_decryption=DEFER_DECRYPTION)
        else:
            return test_sync.TestDbSync.do_sync(self, target_name)

    def wait_for_sync(self):
        """
        Wait for sync to finish.
        """
        wait = 0
        syncer = self.syncer
        if syncer is not None:
            while syncer.syncing:
                time.sleep(WAIT_STEP)
                wait += WAIT_STEP
                if wait >= MAX_WAIT:
                    raise SyncTimeoutError

    def test_db_sync(self):
        """
        Test sync.

        Adapted to check for encrypted content.
        """
        doc1 = self.db1.create_doc_from_json(tests.simple_doc)
        doc2 = self.db2.create_doc_from_json(tests.nested_doc)
        d = self.do_sync('test')

        def _assert_successful_sync(results):
            import time
            # need to give time to the encryption to proceed
            # TODO should implement a defer list to subscribe to the all-decrypted
            # event
            time.sleep(2)
            local_gen_before_sync = results
            self.wait_for_sync()

            gen, _, changes = self.db1.whats_changed(local_gen_before_sync)
            self.assertEqual(1, len(changes))

            self.assertEqual(doc2.doc_id, changes[0][0])
            self.assertEqual(1, gen - local_gen_before_sync)

            self.assertGetEncryptedDoc(
                self.db2, doc1.doc_id, doc1.rev, tests.simple_doc, False)
            self.assertGetEncryptedDoc(
                self.db1, doc2.doc_id, doc2.rev, tests.nested_doc, False)

        d.addCallback(_assert_successful_sync)
        return d

    def test_db_sync_autocreate(self):
        pass
