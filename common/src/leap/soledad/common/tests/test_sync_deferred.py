# -*- coding: utf-8 -*-
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
from urlparse import urljoin

from leap.soledad.common.tests import u1db_tests as tests, ADDRESS
from leap.soledad.common.tests.u1db_tests import test_sync

from leap.soledad.common.document import SoledadDocument
from leap.soledad.common import couch
from leap.soledad.client import target
from leap.soledad.client.sync import SoledadSynchronizer

# Just to make clear how this test is different... :)
DEFER_DECRYPTION = True

WAIT_STEP = 1
MAX_WAIT = 10


from leap.soledad.client.sqlcipher import open as open_sqlcipher
from leap.soledad.common.tests.util import SoledadWithCouchServerMixin
from leap.soledad.common.tests.util import make_soledad_app


DBPASS = "pass"


class BaseSoledadDeferredEncTest(SoledadWithCouchServerMixin):
    """
    Another base class for testing the deferred encryption/decryption during
    the syncs, using the intermediate database.
    """
    defer_sync_encryption = True

    def setUp(self):
        # config info
        self.db1_file = os.path.join(self.tempdir, "db1.u1db")
        self.db_pass = DBPASS
        self.email = ADDRESS

        # get a random prefix for each test, so we do not mess with
        # concurrency during initialization and shutting down of
        # each local db.
        self.rand_prefix = ''.join(
            map(lambda x: random.choice(string.ascii_letters), range(6)))
        # initialize soledad by hand so we can control keys
        self._soledad = self._soledad_instance(
            prefix=self.rand_prefix, user=self.email)

        # open test dbs: db1 will be the local sqlcipher db
        # (which instantiates a syncdb)
        self.db1 = open_sqlcipher(self.db1_file, DBPASS, create=True,
                                  document_factory=SoledadDocument,
                                  crypto=self._soledad._crypto,
                                  defer_encryption=True,
                                  sync_db_key=DBPASS)
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
        import shutil
        shutil.rmtree(os.path.dirname(self._soledad._local_db_path))


#SQLCIPHER_SCENARIOS = [
#    ('http', {
#        #'make_app_with_state': test_sync_target.make_token_soledad_app,
#        'make_app_with_state': make_soledad_app,
#        'make_database_for_test': ts.make_sqlcipher_database_for_test,
#        'copy_database_for_test': ts.copy_sqlcipher_database_for_test,
#        'make_document_for_test': ts.make_document_for_test,
#        'token': True
#        }),
#]


class SyncTimeoutError(Exception):
    """
    Dummy exception to notify timeout during sync.
    """
    pass


class TestSoledadDbSyncDeferredEncDecr(
        BaseSoledadDeferredEncTest,
        test_sync.TestDbSync):
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

    def setUp(self):
        """
        Need to explicitely invoke inicialization on all bases.
        """
        tests.TestCaseWithServer.setUp(self)
        self.main_test_class = test_sync.TestDbSync
        BaseSoledadDeferredEncTest.setUp(self)
        self.startServer()
        self.syncer = None

    def tearDown(self):
        """
        Need to explicitely invoke destruction on all bases.
        """
        BaseSoledadDeferredEncTest.tearDown(self)
        tests.TestCaseWithServer.tearDown(self)

    def do_sync(self, target_name):
        """
        Perform sync using SoledadSynchronizer, SoledadSyncTarget
        and Token auth.
        """
        if self.token:
            extra = dict(creds={'token': {
                'uuid': 'user-uuid',
                'token': 'auth-token',
            }})
            target_url = self.getURL(target_name)
            syncdb = getattr(self.db1, "_sync_db", None)

            syncer = SoledadSynchronizer(
                self.db1,
                target.SoledadSyncTarget(
                    target_url,
                    crypto=self._soledad._crypto,
                    sync_db=syncdb,
                    **extra))
            # Keep a reference to be able to know when the sync
            # has finished.
            self.syncer = syncer
            return syncer.sync(
                autocreate=True, defer_decryption=DEFER_DECRYPTION)
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

        import time
        # need to give time to the encryption to proceed
        # TODO should implement a defer list to subscribe to the all-decrypted
        # event
        time.sleep(2)

        local_gen_before_sync = self.do_sync('test')
        self.wait_for_sync()

        gen, _, changes = self.db1.whats_changed(local_gen_before_sync)
        self.assertEqual(1, len(changes))

        self.assertEqual(doc2.doc_id, changes[0][0])
        self.assertEqual(1, gen - local_gen_before_sync)

        self.assertGetEncryptedDoc(
            self.db2, doc1.doc_id, doc1.rev, tests.simple_doc, False)
        self.assertGetEncryptedDoc(
            self.db1, doc2.doc_id, doc2.rev, tests.nested_doc, False)

    def test_db_sync_autocreate(self):
        pass

load_tests = tests.load_with_scenarios
