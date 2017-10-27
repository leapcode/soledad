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
import sys

from functools import partial

from twisted.enterprise import adbapi
from twisted.internet.defer import DeferredSemaphore
from twisted.python import compat
from zope.proxy import ProxyBase, setProxiedObject

from leap.soledad.common.log import getLogger
from leap.soledad.common.errors import DatabaseAccessError

from . import sqlcipher
from . import pragmas

if sys.version_info[0] < 3:
    from pysqlcipher import dbapi2
else:
    from pysqlcipher3 import dbapi2


logger = getLogger(__name__)


"""
How long the SQLCipher connection should wait for the lock to go away until
raising an exception.
"""
SQLCIPHER_CONNECTION_TIMEOUT = 10

"""
How many times a SQLCipher query should be retried in case of timeout.
"""
SQLCIPHER_MAX_RETRIES = 20


def getConnectionPool(opts, openfun=None, driver="pysqlcipher"):
    """
    Return a connection pool.

    :param opts:
        Options for the SQLCipher connection.
    :type opts: SQLCipherOptions
    :param openfun:
        Callback invoked after every connect() on the underlying DB-API
        object.
    :type openfun: callable
    :param driver:
        The connection driver.
    :type driver: str

    :return: A U1DB connection pool.
    :rtype: U1DBConnectionPool
    """
    if openfun is None and driver == "pysqlcipher":
        openfun = partial(pragmas.set_init_pragmas, opts=opts)
    return U1DBConnectionPool(
        opts,
        # the following params are relayed "as is" to twisted's
        # ConnectionPool.
        "%s.dbapi2" % driver, opts.path, timeout=SQLCIPHER_CONNECTION_TIMEOUT,
        check_same_thread=False, cp_openfun=openfun)


class U1DBConnection(adbapi.Connection):
    """
    A wrapper for a U1DB connection instance.
    """

    u1db_wrapper = sqlcipher.SoledadSQLCipherWrapper
    """
    The U1DB wrapper to use.
    """

    def __init__(self, pool, init_u1db=False):
        """
        :param pool: The pool of connections to that owns this connection.
        :type pool: adbapi.ConnectionPool
        :param init_u1db: Wether the u1db database should be initialized.
        :type init_u1db: bool
        """
        self.init_u1db = init_u1db
        try:
            adbapi.Connection.__init__(self, pool)
        except dbapi2.DatabaseError as e:
            raise DatabaseAccessError(
                'Error initializing connection to sqlcipher database: %s'
                % str(e))

    def reconnect(self):
        """
        Reconnect to the U1DB database.
        """
        if self._connection is not None:
            self._pool.disconnect(self._connection)
        self._connection = self._pool.connect()

        if self.init_u1db:
            self._u1db = self.u1db_wrapper(
                self._connection,
                self._pool.opts)

    def __getattr__(self, name):
        """
        Route the requested attribute either to the U1DB wrapper or to the
        connection.

        :param name: The name of the attribute.
        :type name: str
        """
        if name.startswith('u1db_'):
            attr = re.sub('^u1db_', '', name)
            return getattr(self._u1db, attr)
        else:
            return getattr(self._connection, name)


class U1DBTransaction(adbapi.Transaction):
    """
    A wrapper for a U1DB 'cursor' object.
    """

    def __getattr__(self, name):
        """
        Route the requested attribute either to the U1DB wrapper of the
        connection or to the actual connection cursor.

        :param name: The name of the attribute.
        :type name: str
        """
        if name.startswith('u1db_'):
            attr = re.sub('^u1db_', '', name)
            return getattr(self._connection._u1db, attr)
        else:
            return getattr(self._cursor, name)


class U1DBConnectionPool(adbapi.ConnectionPool):
    """
    Represent a pool of connections to an U1DB database.
    """

    connectionFactory = U1DBConnection
    transactionFactory = U1DBTransaction

    def __init__(self, opts, *args, **kwargs):
        """
        Initialize the connection pool.
        """
        self.opts = opts
        try:
            adbapi.ConnectionPool.__init__(self, *args, **kwargs)
        except dbapi2.DatabaseError as e:
            raise DatabaseAccessError(
                'Error initializing u1db connection pool: %s' % str(e))

        # all u1db connections, hashed by thread-id
        self._u1dbconnections = {}

        # The replica uid, primed by the connections on init.
        self.replica_uid = ProxyBase(None)

        try:
            conn = self.connectionFactory(
                self, init_u1db=True)
            replica_uid = conn._u1db._real_replica_uid
            setProxiedObject(self.replica_uid, replica_uid)
        except DatabaseAccessError as e:
            self.threadpool.stop()
            raise DatabaseAccessError(
                "Error initializing connection factory: %s" % str(e))

    def runU1DBQuery(self, meth, *args, **kw):
        """
        Execute a U1DB query in a thread, using a pooled connection.

        Concurrent threads trying to update the same database may timeout
        because of other threads holding the database lock. Because of this,
        we will retry SQLCIPHER_MAX_RETRIES times and fail after that.

        :param meth: The U1DB wrapper method name.
        :type meth: str

        :return: a Deferred which will fire the return value of
            'self._runU1DBQuery(Transaction(...), *args, **kw)', or a Failure.
        :rtype: twisted.internet.defer.Deferred
        """
        meth = "u1db_%s" % meth
        semaphore = DeferredSemaphore(SQLCIPHER_MAX_RETRIES)

        def _run_interaction():
            return self.runInteraction(
                self._runU1DBQuery, meth, *args, **kw)

        def _errback(failure):
            failure.trap(dbapi2.OperationalError)
            if failure.getErrorMessage() == "database is locked":
                logger.warn("database operation timed out")
                should_retry = semaphore.acquire()
                if should_retry:
                    logger.warn("trying again...")
                    return _run_interaction()
                logger.warn("giving up!")
            return failure

        d = _run_interaction()
        d.addErrback(_errback)
        return d

    def _runU1DBQuery(self, trans, meth, *args, **kw):
        """
        Execute a U1DB query.

        :param trans: An U1DB transaction.
        :type trans: adbapi.Transaction
        :param meth: the U1DB wrapper method name.
        :type meth: str
        """
        meth = getattr(trans, meth)
        return meth(*args, **kw)
        # XXX should return a fetchall?

    # XXX add _runOperation too

    def _runInteraction(self, interaction, *args, **kw):
        """
        Interact with the database and return the result.

        :param interaction:
            A callable object whose first argument is an
            L{adbapi.Transaction}.
        :type interaction: callable
        :return: a Deferred which will fire the return value of
            'interaction(Transaction(...), *args, **kw)', or a Failure.
        :rtype: twisted.internet.defer.Deferred
        """
        tid = self.threadID()
        u1db = self._u1dbconnections.get(tid)
        conn = self.connectionFactory(
            self, init_u1db=not bool(u1db))

        if self.replica_uid is None:
            replica_uid = conn._u1db._real_replica_uid
            setProxiedObject(self.replica_uid, replica_uid)

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
        except Exception:
            excType, excValue, excTraceback = sys.exc_info()
            try:
                conn.rollback()
            except Exception:
                logger.error(None, "Rollback failed")
            compat.reraise(excValue, excTraceback)

    def finalClose(self):
        """
        A final close, only called by the shutdown trigger.
        """
        self.shutdownID = None
        if self.threadpool.started:
            self.threadpool.stop()
        self.running = False
        for conn in self.connections.values():
            self._close(conn)
        for u1db in self._u1dbconnections.values():
            self._close(u1db)
        self.connections.clear()
