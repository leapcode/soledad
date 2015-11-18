#!/usr/bin/env python
# -*- coding: utf-8 -*-
# benchmark_uploads.py
# Copyright (C) 2015 LEAP
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
Run benchmarks for sync (uploads).
"""
import getpass
import sys
import datetime
import subprocess

NUM_ITER = 10
NUM_UPLOADS = 10

RESULTS = []


if __name__ == "__main__":
    user = sys.argv[1]
    passwd = sys.argv[2]
    opts = ("--no-stats --send-num %s --payload-file sample --repeat-payload -p "
            "%s -b /tmp/profile-soledad-upload ") % (NUM_UPLOADS, passwd)

    for i in xrange(NUM_ITER):
        print "[+] ITERATION NUMBER: ", i
        start = datetime.datetime.now()
        cmd = "./profile-sync.py " + opts + user
        print "CALLING", cmd
        result = subprocess.check_call(cmd.split())
        print "EXIT CODE:", result
        end = datetime.datetime.now()
        delta = (end - start)
        RESULTS.append(delta)
        print "[+] SYNC TOOK %s seconds" % delta.seconds

    import numpy
    res = [x.seconds for x in RESULTS]
    print "-------------------------"
    print "SYNC UPLOAD REPORT"
    print "USER:", user
    print "UPLOADS: %s 1K DOCS" % NUM_UPLOADS
    print "ITERATIONS: %s" % NUM_ITER
    print 
    print "mean :", numpy.mean(res)
    print "stdev:", numpy.std(res)
    print "-------------------------"
