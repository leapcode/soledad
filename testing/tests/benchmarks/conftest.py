import base64
import pytest
import random

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
