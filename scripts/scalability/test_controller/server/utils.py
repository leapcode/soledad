#!/usr/bin/env python

from subprocess import check_output
from psutil import Process

args = set([
    '/usr/bin/twistd',
    '--python=/usr/lib/python2.7/dist-packages/leap/soledad/server/server.tac',
])


def get_soledad_server_pid():
    output = check_output(['pidof', 'python'])
    for pid in output.split():
        proc = Process(int(pid))
        cmdline = proc.cmdline()
        if args.issubset(set(cmdline)):
            return int(pid)


if __name__ == '__main__':
    print get_soledad_server_pid()
