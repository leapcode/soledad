#!/usr/bin/env python

"""
Test Controller Server
======================

This script implements a test controller server for scalability tests. It can
be triggered to setup user databases and start and stop monitoring different
kinds of resources (cpu, mem, responsiveness, etc).

HTTP API
--------

The HTTP API is very simple:

  +---------------------+-----------------------------------------------------+
  | POST /setup         | setup server databases for scalability test.        |
  +---------------------+-----------------------------------------------------+
  | POST /cpu?pid=<PID> | start monitoring a process' CPU usage.              |
  +---------------------|-----------------------------------------------------+
  | GET /cpu            | return the cpu percentage used by the process since |
  |                     |  last call to PUT.                                  |
  +---------------------|-----------------------------------------------------+
  | POST /mem?pid=<PID> | start monitoring a process' memory usage.           |
  +---------------------|-----------------------------------------------------+
  | GET /mem            | return mem usage stats used by the process since    |
  |                     | call to PUT.                                        |
  +---------------------+-----------------------------------------------------+

Environment Variables
---------------------

The following environment variables modify the behaviour of the resource
monitor:

    HTTP_PORT - use that port to listen for HTTP requests (default: 7001).
"""

import json
import os
import psutil

from twisted.application import service, internet
from twisted.web import resource, server
from twisted.internet.task import LoopingCall
from twisted.internet.threads import deferToThread
from twisted.logger import Logger

from test_controller.server.user_dbs import ensure_dbs
from test_controller.server.blobs import create_blobs
from test_controller.server.blobs import delete_blobs


DEFAULT_HTTP_PORT = 7001
SUCCESS = json.dumps({'success': True})

logger = Logger(__name__)


#
# Resource Watcher classes (mem, cpu)
#

class ResourceWatcher(object):

    def __init__(self, pid):
        logger.info('%s started for process with PID %d'
                    % (self.__class__.__name__, int(pid)))
        self.loop_call = LoopingCall(self._loop)
        self.process = psutil.Process(pid)
        self.data = []
        self.result = None

    @property
    def running(self):
        return self.loop_call.running

    def _loop(self):
        pass

    def start(self):
        self._start()
        d = self.loop_call.start(self.interval)
        d.addCallback(self._stop)
        return d

    def _start(self):
        pass

    def _stop(self, _):
        raise NotImplementedError

    def stop(self):
        self.loop_call.stop()


class CpuWatcher(ResourceWatcher):

    interval = 1

    def _start(self):
        self.process.cpu_percent()

    def _stop(self, _):
        self.result = {'cpu_percent': self.process.cpu_percent()}


def _mean(l):
    return float(sum(l)) / len(l)


def _std(l):
    if len(l) <= 1:
        return 0
    mean = _mean(l)
    squares = [(x - mean) ** 2 for x in l]
    return (sum(squares) / (len(l) - 1)) ** 0.5


class MemoryWatcher(ResourceWatcher):

    interval = 0.1

    def _loop(self):
        sample = self.process.memory_percent(memtype='rss')
        self.data.append(sample)

    def _stop(self, _):
        stats = {
            'max': max(self.data),
            'min': min(self.data),
            'mean': _mean(self.data),
            'std': _std(self.data),
        }
        self.result = {
            'interval': self.interval,
            'samples': self.data,
            'memory_percent': stats,
        }


#
# Resources for use with "twistd web"
#

class MissingPidError(Exception):

    def __str__(self):
        return "No PID was passed in request"


class InvalidPidError(Exception):

    def __init__(self, pid):
        Exception.__init__(self)
        self.pid = pid

    def __str__(self):
        return "Invalid PID: %r" % self.pid


class MonitorResource(resource.Resource):
    """
    A generic resource-monitor web resource.
    """

    isLeaf = 1

    def __init__(self, watcherClass):
        resource.Resource.__init__(self)
        self.watcherClass = watcherClass
        self.watcher = None

    def _get_pid(self, request):
        if 'pid' not in request.args:
            raise MissingPidError()
        pid = request.args['pid'].pop()
        if not pid.isdigit():
            raise InvalidPidError(pid)
        return int(pid)

    def render_POST(self, request):
        try:
            pid = self._get_pid(request)
        except Exception as e:
            request.setResponseCode(500)
            logger.error('Error processing request: %r' % e)
            return json.dumps({'error': str(e)})
        self._stop_watcher()
        try:
            self.watcher = self.watcherClass(pid)
            self.watcher.start()
            return SUCCESS
        except psutil.NoSuchProcess as e:
            request.setResponseCode(404)
            return json.dumps({'error': str(e)})

    def render_GET(self, request):
        self._stop_watcher()
        if self.watcher:
            return json.dumps(self.watcher.result)
        return json.dumps({})

    def _stop_watcher(self):
        if self.watcher and self.watcher.running:
            self.watcher.stop()


class SetupResource(resource.Resource):

    def render_POST(self, request):
        create = request.args.get('create') or [1000]
        d = ensure_dbs(create=int(create.pop()))
        d.addCallback(self._success, request)
        d.addErrback(self._error, request)
        return server.NOT_DONE_YET

    def _success(self, _, request):
        request.write(SUCCESS)
        request.finish()

    def _error(self, e, request):
        message = e.getErrorMessage() if e.getErrorMessage() else repr(e)
        logger.error('Error processing request: %s' % message)
        request.setResponseCode(500)
        request.write(json.dumps({'error': str(e)}))
        request.finish()


class BlobsResource(resource.Resource):

    def render_POST(self, request):
        action = (request.args.get('action') or ['create']).pop()
        amount = int((request.args.get('amount') or [1000]).pop())
        size = int((request.args.get('size') or [1000]).pop())
        if action == 'create':
            d = deferToThread(create_blobs, '/tmp/soledad-server/blobs',
                              amount, size)
        elif action == 'delete':
            d = deferToThread(delete_blobs, '/tmp/soledad-server/blobs')
        d.addCallback(self._success, request)
        d.addErrback(self._error, request)
        return server.NOT_DONE_YET

    def _success(self, _, request):
        request.write(SUCCESS)
        request.finish()

    def _error(self, e, request):
        message = e.getErrorMessage() if e.getErrorMessage() else repr(e)
        logger.error('Error processing request: %s' % message)
        request.setResponseCode(500)
        request.write(json.dumps({'error': str(e)}))
        request.finish()


class Root(resource.Resource):

    def __init__(self):
        resource.Resource.__init__(self)
        self.putChild('mem', MonitorResource(MemoryWatcher))
        self.putChild('cpu', MonitorResource(CpuWatcher))
        self.putChild('setup', SetupResource())
        self.putChild('blobs', BlobsResource())


application = service.Application("Resource Monitor")
site = server.Site(Root())
port = os.environ.get('HTTP_PORT', DEFAULT_HTTP_PORT)
service = internet.TCPServer(port, site)
service.setServiceParent(application)
