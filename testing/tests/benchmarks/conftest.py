import base64
import numpy
import os
import psutil
import pytest
import random
import threading
import time

from twisted.internet import threads, reactor


# we have to manually setup the events server in order to be able to signal
# events. This is usually done by the enclosing application using soledad
# client (i.e. bitmask client).
from leap.common.events import server
server.ensure_server()


#
# pytest customizations
#

def pytest_addoption(parser):
    parser.addoption(
        "--num-docs", type="int", default=100,
        help="the number of documents to use in performance tests")


# mark benchmark tests using their group names (thanks ionelmc! :)
def pytest_collection_modifyitems(items):
    for item in items:
        bench = item.get_marker("benchmark")
        if bench and bench.kwargs.get('group'):
            group = bench.kwargs['group']
            marker = getattr(pytest.mark, 'benchmark_' + group)
            item.add_marker(marker)


#
# benchmark fixtures
#

@pytest.fixture()
def payload():
    def generate(size):
        random.seed(1337)  # same seed to avoid different bench results
        payload_bytes = bytearray(random.getrandbits(8) for _ in xrange(size))
        # encode as base64 to avoid ascii encode/decode errors
        return base64.b64encode(payload_bytes)[:size]  # remove b64 overhead
    return generate


@pytest.fixture()
def txbenchmark(benchmark):
    def blockOnThread(*args, **kwargs):
        return threads.deferToThread(
            benchmark, threads.blockingCallFromThread,
            reactor, *args, **kwargs)
    return blockOnThread


@pytest.fixture()
def txbenchmark_with_setup(benchmark):
    def blockOnThreadWithSetup(setup, f):
        def blocking_runner(*args, **kwargs):
            return threads.blockingCallFromThread(reactor, f, *args, **kwargs)

        def blocking_setup():
            args = threads.blockingCallFromThread(reactor, setup)
            try:
                return tuple(arg for arg in args), {}
            except TypeError:
                    return ((args,), {}) if args else None

        def bench():
            return benchmark.pedantic(blocking_runner, setup=blocking_setup,
                                      rounds=4, warmup_rounds=1)
        return threads.deferToThread(bench)
    return blockOnThreadWithSetup


#
# resource monitoring
#

class MemoryWatcher(threading.Thread):

    def __init__(self, process, interval):
        threading.Thread.__init__(self)
        self.process = process
        self.interval = interval
        self.samples = []
        self.running = False

    def run(self):
        self.running = True
        while self.running:
            memory = self.process.memory_percent(memtype='rss')
            self.samples.append(memory)
            time.sleep(self.interval)

    def stop(self):
        self.running = False
        self.join()

    def info(self):
        info = {
            'interval': self.interval,
            'samples': self.samples,
            'stats': {},
        }
        for stat in 'max', 'min', 'mean', 'std':
            fun = getattr(numpy, stat)
            info['stats'][stat] = fun(self.samples)
        return info


@pytest.fixture
def monitored_benchmark(benchmark, request):

    def _monitored_benchmark(fun, *args, **kwargs):
        process = psutil.Process(os.getpid())
        memwatch = MemoryWatcher(process, 1)
        memwatch.start()
        process.cpu_percent()
        benchmark.pedantic(
            fun, args=args, kwargs=kwargs,
            rounds=1, iterations=1, warmup_rounds=0)
        memwatch.stop()
        # store results
        benchmark.extra_info['cpu_percent'] = process.cpu_percent()
        benchmark.extra_info['memory_percent'] = memwatch.info()

    return _monitored_benchmark
