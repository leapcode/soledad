from twisted.internet import defer, reactor
from twisted.internet.task import LoopingCall
from twisted.internet.threads import deferToThread


class Watchdog(object):

    DEBUG = False

    def __init__(self, delay=0.01):
        self.delay = delay
        self.loop_call = LoopingCall.withCount(self.watch)
        self.blocked = 0
        self.checks = []
        self.d = None

    def start(self):
        self.debug("\n[watchdog] starting")
        self.loop_call.start(self.delay)
        self.d = defer.Deferred()
        return self.d

    def watch(self, count):
        self.debug("[watchdog] watching (%d)" % count)
        if (self.loop_call.running):
            self.checks.append(deferToThread(self._check, count))

    def _check(self, count):
        # self.debug("[watchdog] _checking (%d)" % count)
        if count > 1:
            self.blocked += count

    def stop(self):
        # delay the actual stop so we make sure at least one check watch will
        # run in the reactor.
        reactor.callLater(2 * self.delay, self._stop)

    @defer.inlineCallbacks
    def _stop(self):
        if not self.loop_call.running:
            return

        self.loop_call.stop()
        yield defer.gatherResults(self.checks)
        self.d.callback(None)

    @property
    def seconds_blocked(self):
        return self.blocked * self.delay

    def debug(self, s):
        if self.DEBUG:
            print(s)
