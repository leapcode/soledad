import functools
import numpy
import os
import psutil
import pytest
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
def txbenchmark(monitored_benchmark):
    def blockOnThread(*args, **kwargs):
        return threads.deferToThread(
            monitored_benchmark, threads.blockingCallFromThread,
            reactor, *args, **kwargs)
    return blockOnThread


@pytest.fixture()
def txbenchmark_with_setup(monitored_benchmark_with_setup):
    def blockOnThreadWithSetup(setup, f, *args, **kwargs):
        def blocking_runner(*args, **kwargs):
            return threads.blockingCallFromThread(reactor, f, *args, **kwargs)

        def blocking_setup():
            args = threads.blockingCallFromThread(reactor, setup)
            try:
                return tuple(arg for arg in args), {}
            except TypeError:
                    return ((args,), {}) if args else None

        def bench():
            return monitored_benchmark_with_setup(
                blocking_runner, setup=blocking_setup,
                rounds=4, warmup_rounds=1, iterations=1,
                args=args, kwargs=kwargs)
        return threads.deferToThread(bench)
    return blockOnThreadWithSetup


#
# resource monitoring
#

class ResourceWatcher(threading.Thread):

    sampling_interval = 0.1

    def __init__(self, watch_memory):
        threading.Thread.__init__(self)
        self.process = psutil.Process(os.getpid())
        self.running = False
        # monitored resources
        self.cpu_percent = None
        self.watch_memory = watch_memory
        self.memory_samples = []
        self.memory_percent = None

    def run(self):
        self.running = True
        self.process.cpu_percent()
        # decide how long to sleep based on need to sample memory
        sleep = self.sampling_interval if not self.watch_memory else 1
        while self.running:
            if self.watch_memory:
                sample = self.process.memory_percent(memtype='rss')
                self.memory_samples.append(sample)
            time.sleep(sleep)

    def stop(self):
        self.running = False
        self.join()
        # save cpu usage info
        self.cpu_percent = self.process.cpu_percent()
        # save memory usage info
        if self.watch_memory:
            memory_percent = {
                'sampling_interval': self.sampling_interval,
                'samples': self.memory_samples,
                'stats': {},
            }
            for stat in 'max', 'min', 'mean', 'std':
                fun = getattr(numpy, stat)
                memory_percent['stats'][stat] = fun(self.memory_samples)
            self.memory_percent = memory_percent


def _monitored_benchmark(benchmark_fixture, benchmark_function, request,
                         *args, **kwargs):
    # setup resource monitoring
    watch_memory = _watch_memory(request)
    watcher = ResourceWatcher(watch_memory)
    watcher.start()
    # run benchmarking function
    benchmark_function(*args, **kwargs)
    # store results
    watcher.stop()
    benchmark_fixture.extra_info.update({
        'cpu_percent': watcher.cpu_percent
    })
    if watch_memory:
        benchmark_fixture.extra_info.update({
            'memory_percent': watcher.memory_percent,
        })
    # add docstring info
    if request.scope == 'function':
        fun = request.function
        doc = fun.__doc__ or ''
        benchmark_fixture.extra_info.update({'doc': doc.strip()})


def _watch_memory(request):
    return request.config.getoption('--watch-memory')


@pytest.fixture
def monitored_benchmark(benchmark, request):
    return functools.partial(
        _monitored_benchmark, benchmark, benchmark, request)


@pytest.fixture
def monitored_benchmark_with_setup(benchmark, request, *args, **kwargs):
    return functools.partial(
        _monitored_benchmark, benchmark, benchmark.pedantic, request,
        *args, **kwargs)
