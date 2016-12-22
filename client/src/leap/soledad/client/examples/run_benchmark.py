"""
Run a mini-benchmark between regular api and dbapi
"""
import commands
import os
import time

TMPDIR = os.environ.get("TMPDIR", "/tmp")
CSVFILE = 'bench.csv'

cmd = "SILENT=1 TIMES={times} TMPDIR={tmpdir} python ./use_{version}api.py"


def parse_time(r):
    return r.split('\n')[-1]


with open(CSVFILE, 'w') as log:

    for times in range(0, 10000, 500):
        cmd1 = cmd.format(times=times, tmpdir=TMPDIR, version="")
        sync_time = parse_time(commands.getoutput(cmd1))

        cmd2 = cmd.format(times=times, tmpdir=TMPDIR, version="adb")
        async_time = parse_time(commands.getoutput(cmd2))

        print times, sync_time, async_time
        log.write("%s, %s, %s\n" % (times, sync_time, async_time))
        log.flush()
        time.sleep(2)
