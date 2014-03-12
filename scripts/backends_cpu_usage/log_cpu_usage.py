#!/usr/bin/python


# Get the CPU usage and print to file.


import psutil
import time
import argparse
import os
import threading


class LogCpuUsage(threading.Thread):

    def __init__(self, fname):
        threading.Thread.__init__(self)
        self._stopped = True
        self._fname = fname 

    def run(self):
        self._stopped = False
        with open(self._fname, 'w') as f:
            start = time.time()
            while self._stopped is False:
                now = time.time()
                f.write("%f %f\n" % ((now - start), psutil.cpu_percent()))
                time.sleep(0.01)

    def stop(self):
        self._stopped = True


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('file', help='where to save output')
    args = parser.parse_args()

    if os.path.isfile(args.file):
        replace = raw_input('File %s exists, replace it (y/N)? ' % args.file)
        if replace.lower() != 'y':
            print 'Bailing out.'
            exit(1)
    
    log_cpu = LogCpuUsage(args.file)
    log_cpu.run()
