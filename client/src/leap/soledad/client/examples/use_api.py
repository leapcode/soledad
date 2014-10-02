# -*- coding: utf-8 -*-
# use_api.py
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
Example of use of the soledad api.
"""
from __future__ import print_function
import datetime
import os

from leap.soledad.client import sqlcipher
from leap.soledad.client.sqlcipher import SQLCipherOptions


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
db = sqlcipher.SQLCipherDatabase(opts)


def allDone():
    debug("ALL DONE!")


for i in range(times):
    doc = {"number": i,
           "payload": open('manifest.phk').read()}
    d = db.create_doc(doc)
    debug(d.doc_id, d.content['number'])

debug("Count", len(db.get_all_docs()[1]))
if silent:
    end_time = datetime.datetime.now()
    print((end_time - start_time).total_seconds())

allDone()
