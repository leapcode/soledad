# -*- coding: utf-8 -*-
# adbapi.py
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
import re
import os
import sys

from functools import partial

from twisted.enterprise import adbapi
from twisted.python import log
from zope.proxy import ProxyBase, setProxiedObject

from leap.soledad.client import sqlcipher as soledad_sqlcipher


DEBUG_SQL = os.environ.get("LEAP_DEBUG_SQL")
if DEBUG_SQL:
    log.startLogging(sys.stdout)


def getConnectionPool(opts, openfun=None, driver="pysqlcipher"):
    if openfun is None and driver == "pysqlcipher":
        openfun = partial(soledad_sqlcipher.set_init_pragmas, opts=opts)
    return U1DBConnectionPool(
        "%s.dbapi2" % driver, database=opts.path,
        check_same_thread=False, cp_openfun=openfun)


class U1DBConnection(adbapi.Connection):

    u1db_wrapper = soledad_sqlcipher.SoledadSQLCipherWrapper

    def __init__(self, pool, init_u1db=False):
        self.init_u1db = init_u1db
        adbapi.Connection.__init__(self, pool)

    def reconnect(self):
        if self._connection is not None:
            self._pool.disconnect(self._connection)
        self._connection = self._pool.connect()

        if self.init_u1db:
            self._u1db = self.u1db_wrapper(self._connection)

    def __getattr__(self, name):
        if name.startswith('u1db_'):
            meth = re.sub('^u1db_', '', name)
            return getattr(self._u1db, meth)
        else:
            return getattr(self._connection, name)


class U1DBTransaction(adbapi.Transaction):

    def __getattr__(self, name):
        if name.startswith('u1db_'):
            meth = re.sub('^u1db_', '', name)
            return getattr(self._connection._u1db, meth)
        else:
            return getattr(self._cursor, name)


class U1DBConnectionPool(adbapi.ConnectionPool):

    connectionFactory = U1DBConnection
    transactionFactory = U1DBTransaction

    def __init__(self, *args, **kwargs):
        adbapi.ConnectionPool.__init__(self, *args, **kwargs)
        # all u1db connections, hashed by thread-id
        self._u1dbconnections = {}

        # The replica uid, primed by the connections on init.
        self.replica_uid = ProxyBase(None)

    def runU1DBQuery(self, meth, *args, **kw):
        meth = "u1db_%s" % meth
        return self.runInteraction(self._runU1DBQuery, meth, *args, **kw)

    def _runU1DBQuery(self, trans, meth, *args, **kw):
        meth = getattr(trans, meth)
        return meth(*args, **kw)

    def _runInteraction(self, interaction, *args, **kw):
        tid = self.threadID()
        u1db = self._u1dbconnections.get(tid)
        conn = self.connectionFactory(self, init_u1db=not bool(u1db))

        if self.replica_uid is None:
            replica_uid = conn._u1db._real_replica_uid
            setProxiedObject(self.replica_uid, replica_uid)
            print "GOT REPLICA UID IN DBPOOL", self.replica_uid

        if u1db is None:
            self._u1dbconnections[tid] = conn._u1db
        else:
            conn._u1db = u1db

        trans = self.transactionFactory(self, conn)
        try:
            result = interaction(trans, *args, **kw)
            trans.close()
            conn.commit()
            return result
        except:
            excType, excValue, excTraceback = sys.exc_info()
            try:
                conn.rollback()
            except:
                log.err(None, "Rollback failed")
            raise excType, excValue, excTraceback

    def finalClose(self):
        self.shutdownID = None
        self.threadpool.stop()
        self.running = False
        for conn in self.connections.values():
            self._close(conn)
        for u1db in self._u1dbconnections.values():
            self._close(u1db)
        self.connections.clear()
