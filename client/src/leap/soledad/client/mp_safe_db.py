# -*- coding: utf-8 -*-
# crypto.py
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
Multiprocessing-safe SQLite database.
"""


from threading import Thread
from Queue import Queue
from pysqlcipher import dbapi2


# Thanks to http://code.activestate.com/recipes/526618/

class MPSafeSQLiteDB(Thread):
    """
    A multiprocessing-safe SQLite database accessor.
    """

    CLOSE = "--close--"
    NO_MORE = "--no more--"

    def __init__(self, db_path):
        """
        Initialize the process
        """
        Thread.__init__(self)
        self._db_path = db_path
        self._requests = Queue()
        self.start()

    def run(self):
        """
        Run the multiprocessing-safe database accessor.
        """
        conn = dbapi2.connect(self._db_path)
        while True:
            req, arg, res = self._requests.get()
            if req == self.CLOSE:
                break
            with conn:
                cursor = conn.cursor()
                cursor.execute(req, arg)
                if res:
                    for rec in cursor.fetchall():
                        res.put(rec)
                    res.put(self.NO_MORE)
        conn.close()

    def execute(self, req, arg=None, res=None):
        """
        Execute a request on the database.

        :param req: The request to be executed.
        :type req: str
        :param arg: The arguments for the request.
        :type arg: tuple
        :param res: A queue to write request results.
        :type res: multiprocessing.Queue
        """
        self._requests.put((req, arg or tuple(), res))

    def select(self, req, arg=None):
        """
        Run a select query on the database and yield results.

        :param req: The request to be executed.
        :type req: str
        :param arg: The arguments for the request.
        :type arg: tuple
        """
        res = Queue()
        self.execute(req, arg, res)
        while True:
            rec=res.get()
            if rec == self.NO_MORE:
                break
            yield rec

    def close(self):
        """
        Close the database connection.
        """
        self.execute(self.CLOSE)
        self.join()

    def cursor(self):
        """
        Return a fake cursor object.

        Not really a cursor, but allows for calling db.cursor().execute().

        :return: Self.
        :rtype: MPSafeSQLiteDatabase
        """
        return self
