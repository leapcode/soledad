# -*- coding: utf-8 -*-
# measure_index_times.py
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
Measure u1db retrieval times for different u1db index situations.
"""
from __future__ import print_function
from functools import partial
import datetime
import hashlib
import os
import sys

from twisted.internet import defer, reactor

from leap.soledad.client import adbapi
from leap.soledad.client.sqlcipher import SQLCipherOptions
from leap.soledad.common import l2db


folder = os.environ.get("TMPDIR", "tmp")
numdocs = int(os.environ.get("DOCS", "1000"))
silent = os.environ.get("SILENT", False)
tmpdb = os.path.join(folder, "test.soledad")


sample_file = os.environ.get("SAMPLE", "hacker_crackdown.txt")
sample_path = os.path.join(os.curdir, sample_file)

try:
    with open(sample_file) as f:
        SAMPLE = f.readlines()
except Exception:
    print("[!] Problem opening sample file. Did you download "
          "the sample, or correctly set 'SAMPLE' env var?")
    sys.exit(1)

if numdocs > len(SAMPLE):
    print("[!] Sorry! The requested DOCS number is larger than "
          "the num of lines in our sample file")
    sys.exit(1)


def debug(*args):
    if not silent:
        print(*args)


debug("[+] db path:", tmpdb)
debug("[+] num docs", numdocs)

if os.path.isfile(tmpdb):
    debug("[+] Removing existing db file...")
    os.remove(tmpdb)

start_time = datetime.datetime.now()

opts = SQLCipherOptions(tmpdb, "secret", create=True)
dbpool = adbapi.getConnectionPool(opts)


def createDoc(doc, doc_id):
    return dbpool.runU1DBQuery("create_doc", doc, doc_id=doc_id)


db_indexes = {
    'by-chash': ['chash'],
    'by-number': ['number']}


def create_indexes(_):
    deferreds = []
    for index, definition in db_indexes.items():
        d = dbpool.runU1DBQuery("create_index", index, *definition)
        deferreds.append(d)
    return defer.gatherResults(deferreds)


class TimeWitness(object):
    def __init__(self, init_time):
        self.init_time = init_time

    def get_time_count(self):
        return datetime.datetime.now() - self.init_time


def get_from_index(_):
    init_time = datetime.datetime.now()
    debug("GETTING FROM INDEX...", init_time)

    def printValue(res, time):
        print("RESULT->", res)
        print("Index Query Took: ", time.get_time_count())
        return res

    d = dbpool.runU1DBQuery(
        "get_doc",
        # "1150c7f10fabce0a57ce13071349fc5064f15bdb0cc1bf2852f74ef3f103aff5")
        # XXX this is line 89 from the hacker crackdown...
        # Should accept any other optional hash as an enviroment variable.
        "57793320d4997a673fc7062652da0596c36a4e9fbe31310d2281e67d56d82469")
    d.addCallback(printValue, TimeWitness(init_time))
    return d


def getAllDocs():
    return dbpool.runU1DBQuery("get_all_docs")


def errBack(e):
    debug("[!] ERROR FOUND!!!")
    e.printTraceback()
    reactor.stop()


def countDocs(_):
    debug("counting docs...")
    d = getAllDocs()
    d.addCallbacks(printResult, errBack)
    d.addCallbacks(allDone, errBack)
    return d


def printResult(r, **kwargs):
    if kwargs:
        debug(*kwargs.values())
    elif isinstance(r, l2db.Document):
        debug(r.doc_id, r.content['number'])
    else:
        len_results = len(r[1])
        debug("GOT %s results" % len(r[1]))

        if len_results == numdocs:
            debug("ALL GOOD")
        else:
            debug("[!] MISSING DOCS!!!!!")
            raise ValueError("We didn't expect this result len")


def allDone(_):
    debug("ALL DONE!")

    end_time = datetime.datetime.now()
    print((end_time - start_time).total_seconds())
    reactor.stop()


def insert_docs(_):
    deferreds = []
    for i in range(numdocs):
        payload = SAMPLE[i]
        chash = hashlib.sha256(payload).hexdigest()
        doc = {"number": i, "payload": payload, 'chash': chash}
        d = createDoc(doc, doc_id=chash)
        d.addCallbacks(partial(printResult, i=i, chash=chash, payload=payload),
                       lambda e: e.printTraceback())
        deferreds.append(d)
    return defer.gatherResults(deferreds, consumeErrors=True)


d = create_indexes(None)
d.addCallback(insert_docs)
d.addCallback(get_from_index)
d.addCallback(countDocs)

reactor.run()
