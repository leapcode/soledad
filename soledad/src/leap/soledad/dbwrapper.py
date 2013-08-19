# -*- coding: utf-8 -*-
# dbwrapper.py
# Copyright (C) 2013 LEAP
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
Thread-safe wrapper for sqlite/pysqlcipher.

*TODO*
At some point we surely will want to switch to a twisted way of dealing
with this, using defers and proper callbacks. But I had this tested for
some time so postponing that refactor.
"""
import logging
import threading
import Queue

import exceptions

from functools import partial

from leap.soledad import sqlcipher

logger = logging.getLogger(__name__)


class SQLCipherWrapper(threading.Thread):

    k_lock = threading.Lock()

    def __init__(self, *args, **kwargs):
        """
        Initializes a wrapper that proxies method and attribute
        access to an underlying SQLCipher instance. We instantiate sqlcipher
        in a thread, and all method accesses communicate with it using a
        Queue.

        :param *args: position arguments to pass to pysqlcipher initialization
        :type args: tuple

        :param **kwargs: keyword arguments to pass to pysqlcipher
                         initialization
        :type kwargs: dict
        """
        threading.Thread.__init__(self)
        self._lock = threading.Lock()
        self._db = None
        self._wrargs = args, kwargs

        self._queue = Queue.Queue()
        self._stopped = threading.Event()

        self.start()

    def _init_db(self):
        """
        Initializes sqlcipher database.

        This is called on a separate thread.
        """
        # instantiate u1db
        args, kwargs = self._wrargs
        with self.k_lock:
            try:
                self._db = sqlcipher.open(*args, **kwargs)
                print "init ok"
            except Exception as exc:
                logger.debug("Error in init_db: %r" % (exc,))
                self._stopped.set()
                raise exc

    def run(self):
        """
        Main loop for the sqlcipher thread.
        """
        END_METHODS = ("__end_thread", "_SQLCipherWrapper__end_thread")
        logger.debug("SQLCipherWrapper thread started.")
        logger.debug("Initializing sqlcipher")

        #ct = 0
        #started = False

        try:
            self._init_db()
        except:
            logger.error("Failed to init db.")
            print "error on init"
            # XXX should raise?

        while True:

            #if self._db is None:
                #if started:
                    #break
                #if ct > 10:
                    #break  # XXX DEBUG
                #logger.debug('db not ready yet, waiting...')
                #print "db not ready, wait..."
                #time.sleep(1)
                #ct += 1

            if self._db is None:
                print "db not initialized!"

            #started = True
            with self._lock:

                try:
                    # XXX not getting args...
                    mth, q, wrargs = self._queue.get()  # False?
                except:
                    print "Exception getting args"
                    logger.error("exception getting args from queue")
                    continue

                print "mth: ", mth
                res = None
                attr = getattr(self._db, mth, None)
                if not attr:
                    if mth not in END_METHODS:
                        logger.error('method %s does not exist' % (mth,))
                        res = AttributeError(
                            "_db instance has no attribute %s" % mth)

                elif callable(attr):
                    # invoke the method with the passed args
                    args = wrargs.get('args', [])
                    kwargs = wrargs.get('kwargs', {})
                    try:
                        res = attr(*args, **kwargs)
                    except Exception as e:
                        logger.error(
                            "Error on proxied method %s: '%r'." % (
                            attr, e))
                        res = e
                else:
                    # non-callable attribute
                    res = attr
                #logger.debug('returning proxied db call...')
                print "putting res: ", res
                q.put(res)

                if mth in END_METHODS:
                    logger.debug('ending thread')
                    break

        logger.debug("SQLCipherWrapper thread terminated.")
        print "SQLWRAPPER TERMINATED"
        self._stopped.set()

    def close(self):
        """
        Closes the sqlcipher database and finishes the thread. This method
        should always be called explicitely.
        """
        self.__getattr__('close')()
        self.__end_thread()

    def __getattr__(self, attr):
        """
        Returns _db proxied attributes.
        """

        def __proxied_mth(method, *args, **kwargs):
            SQLWRAPPER_METHOD_TIMEOUT = 20  # in seconds
            if not self._stopped.isSet():
                wrargs = {'args': args, 'kwargs': kwargs}
                q = Queue.Queue()
                print "put meth"
                with self.k_lock:
                    self._queue.put((method, q, wrargs))
                    try:
                        # XXX this is blocking
                        res = q.get(timeout=SQLWRAPPER_METHOD_TIMEOUT)
                        q.task_done()
                    except Queue.Empty:
                        res = None
                    print "got result"

                if isinstance(res, exceptions.BaseException):
                    # XXX should get the original bt
                    raise res
                return res
            else:
                print "called but stopped!"
                logger.warning("tried to call proxied meth "
                               "but stopped is set: %s" %
                               (method,))

        rgetattr = object.__getattribute__

        if attr != "_db":
            proxied = partial(__proxied_mth, attr)
            return proxied

        # fallback to regular behavior
        return rgetattr(self, attr)

    def __del__(self):
        """
        Closes the thread upon object destruction.

        Do not trust this get called. No guarantees given. Because of a funny
        dance with the refs and the way the gc works, we should be calling the
        close method explicitely.
        """
        self.close()
