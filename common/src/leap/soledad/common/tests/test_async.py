# -*- coding: utf-8 -*-
# test_async.py
# Copyright (C) 2013, 2014 LEAP
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


import os
import hashlib

from twisted.internet import defer

from leap.soledad.common.tests.util import BaseSoledadTest
from leap.soledad.client import adbapi
from leap.soledad.client.sqlcipher import SQLCipherOptions


class ASyncSQLCipherRetryTestCase(BaseSoledadTest):
    """
    Test asynchronous SQLCipher operation.
    """

    NUM_DOCS = 5000

    def _get_dbpool(self):
        tmpdb = os.path.join(self.tempdir, "test.soledad")
        opts = SQLCipherOptions(tmpdb, "secret", create=True)
        return adbapi.getConnectionPool(opts)

    def _get_sample(self):
        if not getattr(self, "_sample", None):
            dirname = os.path.dirname(os.path.realpath(__file__))
            sample_file = os.path.join(dirname, "hacker_crackdown.txt")
            with open(sample_file) as f:
                self._sample = f.readlines()
        return self._sample

    def test_concurrent_puts_fail_with_few_retries_and_small_timeout(self):
        """
        Test if concurrent updates to the database with small timeout and
        small number of retries fail with "database is locked" error.

        Many concurrent write attempts to the same sqlcipher database may fail
        when the timeout is small and there are no retries. This test will
        pass if any of the attempts to write the database fail.

        This test is much dependent on the environment and its result intends
        to contrast with the test for the workaround for the "database is
        locked" problem, which is addressed by the "test_concurrent_puts" test
        below.

        If this test ever fails, it means that either (1) the platform where
        you are running is it very powerful and you should try with an even
        lower timeout value, or (2) the bug has been solved by a better
        implementation of the underlying database pool, and thus this test
        should be removed from the test suite.
        """

        old_timeout = adbapi.SQLCIPHER_CONNECTION_TIMEOUT
        old_max_retries = adbapi.SQLCIPHER_MAX_RETRIES

        adbapi.SQLCIPHER_CONNECTION_TIMEOUT = 1
        adbapi.SQLCIPHER_MAX_RETRIES = 1

        dbpool = self._get_dbpool()

        def _create_doc(doc):
            return dbpool.runU1DBQuery("create_doc", doc)

        def _insert_docs():
            deferreds = []
            for i in range(self.NUM_DOCS):
                payload = self._get_sample()[i]
                chash = hashlib.sha256(payload).hexdigest()
                doc = {"number": i, "payload": payload, 'chash': chash}
                d = _create_doc(doc)
                deferreds.append(d)
            return defer.gatherResults(deferreds, consumeErrors=True)

        def _errback(e):
            if e.value[0].getErrorMessage() == "database is locked":
                adbapi.SQLCIPHER_CONNECTION_TIMEOUT = old_timeout
                adbapi.SQLCIPHER_MAX_RETRIES = old_max_retries
                return defer.succeed("")
            raise Exception

        d = _insert_docs()
        d.addCallback(lambda _: dbpool.runU1DBQuery("get_all_docs"))
        d.addErrback(_errback)
        return d

    def test_concurrent_puts(self):
        """
        Test that many concurrent puts succeed.

        Currently, there's a known problem with the concurrent database pool
        which is that many concurrent attempts to write to the database may
        fail when the lock timeout is small and when there are no (or few)
        retries. We currently workaround this problem by increasing the
        timeout and the number of retries.

        Should this test ever fail, it probably means that the timeout and/or
        number of retries should be increased for the platform you're running
        the test. If the underlying database pool is ever fixed, then the test
        above will fail and we should remove this comment from here.
        """

        dbpool = self._get_dbpool()

        def _create_doc(doc):
            return dbpool.runU1DBQuery("create_doc", doc)

        def _insert_docs():
            deferreds = []
            for i in range(self.NUM_DOCS):
                payload = self._get_sample()[i]
                chash = hashlib.sha256(payload).hexdigest()
                doc = {"number": i, "payload": payload, 'chash': chash}
                d = _create_doc(doc)
                deferreds.append(d)
            return defer.gatherResults(deferreds, consumeErrors=True)

        def _count_docs(results):
            _, docs = results
            if self.NUM_DOCS == len(docs):
                return defer.succeed("")
            raise Exception

        d = _insert_docs()
        d.addCallback(lambda _: dbpool.runU1DBQuery("get_all_docs"))
        d.addCallback(_count_docs)
        return d
