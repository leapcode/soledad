# -*- coding: utf-8 -*-
# use_adbapi.py
# Copyright (C) 2014 LEAP
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
Example of use of the asynchronous soledad api.
"""
from __future__ import print_function
import datetime
import os

from twisted.internet import defer, reactor

from leap.soledad.client import adbapi
from leap.soledad.client._db.sqlcipher import SQLCipherOptions
from leap.soledad.common import l2db


folder = os.environ.get("TMPDIR", "tmp")
times = int(os.environ.get("TIMES", "1000"))
silent = os.environ.get("SILENT", False)

tmpdb = os.path.join(folder, "test.soledad")


def debug(*args):
    if not silent:
        print(*args)


debug("[+] db path:", tmpdb)
debug("[+] times", times)

if os.path.isfile(tmpdb):
    debug("[+] Removing existing db file...")
    os.remove(tmpdb)

start_time = datetime.datetime.now()

opts = SQLCipherOptions(tmpdb, "secret", create=True)
dbpool = adbapi.getConnectionPool(opts)


def createDoc(doc):
    return dbpool.runU1DBQuery("create_doc", doc)


def getAllDocs():
    return dbpool.runU1DBQuery("get_all_docs")


def countDocs(_):
    debug("counting docs...")
    d = getAllDocs()
    d.addCallbacks(printResult, lambda e: e.printTraceback())
    d.addBoth(allDone)


def printResult(r):
    if isinstance(r, l2db.Document):
        debug(r.doc_id, r.content['number'])
    else:
        len_results = len(r[1])
        debug("GOT %s results" % len(r[1]))

        if len_results == times:
            debug("ALL GOOD")
        else:
            raise ValueError("We didn't expect this result len")


def allDone(_):
    debug("ALL DONE!")
    if silent:
        end_time = datetime.datetime.now()
        print((end_time - start_time).total_seconds())
    reactor.stop()


deferreds = []
payload = open('manifest.phk').read()

for i in range(times):
    doc = {"number": i, "payload": payload}
    d = createDoc(doc)
    d.addCallbacks(printResult, lambda e: e.printTraceback())
    deferreds.append(d)


all_done = defer.gatherResults(deferreds, consumeErrors=True)
all_done.addCallback(countDocs)

reactor.run()
