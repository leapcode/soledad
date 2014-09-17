# -*- coding: utf-8 -*-
# sqlcipher.py
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
"""
An asyncrhonous interface to soledad using sqlcipher backend.
It uses twisted.enterprise.adbapi.

"""
import os
import sys

from twisted.enterprise import adbapi
from twisted.python import log

DEBUG_SQL = os.environ.get("LEAP_DEBUG_SQL")
if DEBUG_SQL:
    log.startLogging(sys.stdout)


def getConnectionPool(db=None, key=None):
    return SQLCipherConnectionPool(
        "pysqlcipher.dbapi2", database=db, key=key, check_same_thread=False)


class SQLCipherConnectionPool(adbapi.ConnectionPool):

    key = None

    def connect(self):
        """
        Return a database connection when one becomes available.

        This method blocks and should be run in a thread from the internal
        threadpool. Don't call this method directly from non-threaded code.
        Using this method outside the external threadpool may exceed the
        maximum number of connections in the pool.

        :return: a database connection from the pool.
        """
        self.noisy = DEBUG_SQL

        tid = self.threadID()
        conn = self.connections.get(tid)

        if self.key is None:
            self.key = self.connkw.pop('key', None)

        if conn is None:
            if self.noisy:
                log.msg('adbapi connecting: %s %s%s' % (self.dbapiName,
                                                        self.connargs or '',
                                                        self.connkw or ''))
            conn = self.dbapi.connect(*self.connargs, **self.connkw)

            # XXX we should hook here all OUR SOLEDAD pragmas -----
            conn.cursor().execute("PRAGMA key=%s" % self.key)
            conn.commit()
            # -----------------------------------------------------
            # XXX profit of openfun isntead???

            if self.openfun is not None:
                self.openfun(conn)
            self.connections[tid] = conn
        return conn
