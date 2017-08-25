# -*- coding: utf-8 -*-
# test_tac.py
# Copyright (C) 2017 LEAP
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
"""
Tests for the localhost/public APIs using .tac file.
See docs/auth.rst
"""


import os
import signal
import socket
import pytest
import treq

from twisted.trial import unittest
from twisted.internet import defer, reactor
from twisted.internet.protocol import ProcessProtocol
from twisted.web.client import Agent


TAC_FILE_PATH = ('..', '..', '..', '..', 'pkg', 'server.tac')
TAC_FILE_PATH = os.path.abspath(os.path.join(__file__, *TAC_FILE_PATH))


class TacServerTestCase(unittest.TestCase):

    def test_tac_file_exists(self):
        msg = "server.tac used on this test case was expected to be at %s"
        self.assertTrue(os.path.isfile(TAC_FILE_PATH), msg % TAC_FILE_PATH)

    @defer.inlineCallbacks
    def test_local_public_default_ports_on_server_tac(self):
        yield self._spawnServer()
        result = yield self._get('http://localhost:2323/incoming')
        fail_msg = "Localhost endpoint must require authentication!"
        self.assertEquals(401, result.code, fail_msg)

        public_endpoint_url = 'http://%s:2424/' % self._get_public_ip()
        result = yield self._get(public_endpoint_url)
        self.assertEquals(200, result.code, "server info not accessible")

        result = yield self._get(public_endpoint_url + 'other')
        self.assertEquals(401, result.code, "public server lacks auth!")

        public_using_local_port_url = 'http://%s:2323/' % self._get_public_ip()
        with pytest.raises(Exception):
            yield self._get(public_using_local_port_url)

    def _spawnServer(self):
        protocol = ProcessProtocol()
        env = os.environ.get('VIRTUAL_ENV', '/usr')
        executable = os.path.join(env, 'bin', 'twistd')
        no_pid_argument = '--pidfile='
        args = [executable, no_pid_argument, '-noy', TAC_FILE_PATH]
        t = reactor.spawnProcess(protocol, executable, args)
        self.addCleanup(os.kill, t.pid, signal.SIGKILL)
        self.addCleanup(t.loseConnection)
        return self._sleep(1)  # it takes a while to start server

    def _sleep(self, time):
        d = defer.Deferred()
        reactor.callLater(time, d.callback, True)
        return d

    def _get(self, *args, **kwargs):
        kwargs['agent'] = Agent(reactor)
        return treq.get(*args, **kwargs)

    def _get_public_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
