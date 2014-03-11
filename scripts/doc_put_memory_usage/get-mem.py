#!/usr/bin/python


import psutil
import time


delta = 50 * 60
start = time.time()

while True:
    now = time.time()
    print "%s %s" % (now - start, psutil.phymem_usage().used)
    time.sleep(0.1)
    if now > start + delta:
        break
