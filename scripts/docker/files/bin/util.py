import re
import psutil
import time
import threading
import argparse
import pytz
import datetime


class ValidateUserHandle(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        m = re.compile('^([^@]+)@([^@]+\.[^@]+)$')
        res = m.match(values)
        if res == None:
            parser.error('User handle should have the form user@provider.')
        setattr(namespace, 'username', res.groups()[0])
        setattr(namespace, 'provider', res.groups()[1])


class StatsLogger(threading.Thread):

    def __init__(self, name, fname, procs=[], interval=0.01):
        threading.Thread.__init__(self)
        self._stopped = True
        self._name = name
        self._fname = fname
        self._procs = self._find_procs(procs)
        self._interval = interval

    def _find_procs(self, procs):
        return filter(lambda p: p.name in procs, psutil.process_iter())

    def run(self):
        self._stopped = False
        with open(self._fname, 'w') as f:
            self._start = time.time()
            f.write(self._make_header())
            while self._stopped is False:
                f.write('%s %s\n' %
                    (self._make_general_stats(), self._make_proc_stats()))
                time.sleep(self._interval)
            f.write(self._make_footer())

    def _make_general_stats(self):
        now = time.time()
        stats = []
        stats.append("%f" % (now - self._start))   # elapsed time
        stats.append("%f" % psutil.cpu_percent())  # total cpu
        stats.append("%f" % psutil.virtual_memory().percent)  # total memory
        return ' '.join(stats)

    def _make_proc_stats(self):
        stats = []
        for p in self._procs:
            stats.append('%f' % p.get_cpu_percent())     # proc cpu
            stats.append('%f' % p.get_memory_percent())  # proc memory
        return ' '.join(stats)

    def _make_header(self):
        header = []
        header.append('# test_name: %s' % self._name)
        header.append('# start_time: %s' %  datetime.datetime.now(pytz.utc))
        header.append(
            '# elapsed_time total_cpu total_memory proc_cpu proc_memory ')
        return '\n'.join(header) + '\n'

    def _make_footer(self):
        footer = []
        footer.append('# end_time: %s' % datetime.datetime.now(pytz.utc))
        return '\n'.join(footer)

    def stop(self):
        self._stopped = True


