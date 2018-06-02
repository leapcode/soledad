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

from pkg_resources import resource_filename
from twisted.trial import unittest
from twisted.internet import defer, reactor
from twisted.internet.protocol import ProcessProtocol
from twisted.web.client import Agent


TAC_FILE_PATH = resource_filename('leap.soledad.server', 'server.tac')


@pytest.mark.needs_couch
@pytest.mark.usefixtures("couch_url")
class TacServerTestCase(unittest.TestCase):

    def test_tac_file_exists(self):
        msg = "server.tac used on this test case was expected to be at %s"
        self.assertTrue(os.path.isfile(TAC_FILE_PATH), msg % TAC_FILE_PATH)

    @defer.inlineCallbacks
    def test_local_public_default_ports_on_server_tac(self):
        yield self._spawnServer()
        result = yield self._get('http://localhost:2525/incoming')
        fail_msg = "Localhost endpoint must require authentication!"
        self.assertEquals(401, result.code, fail_msg)

        public_endpoint_url = 'http://%s:2424/' % self._get_public_ip()
        result = yield self._get(public_endpoint_url)
        self.assertEquals(200, result.code, "server info not accessible")

        result = yield self._get(public_endpoint_url + 'other')
        self.assertEquals(401, result.code, "public server lacks auth!")

        public_using_local_port_url = 'http://%s:2525/' % self._get_public_ip()
        with pytest.raises(Exception):
            yield self._get(public_using_local_port_url)

    def _spawnServer(self):

        # Format the following command:
        #   /path/to/twistd --pidfile= -noy /path/to/server.tac
        path = os.environ.get('VIRTUAL_ENV', '/usr')
        twistd = os.path.join(path, 'bin', 'twistd')
        args = [twistd, '--pidfile=', '-noy', TAC_FILE_PATH]

        # Use a special environment when running twistd that allow passing of
        # couch url using environment variable, used by gitlab ci with docker
        env = {
            'DEBUG_SERVER': 'yes',  # run Users API on port 2424 without TLS
            'SOLEDAD_COUCH_URL': self.couch_url,  # used by gitlab ci
        }

        protocol = ProcessProtocol()
        proc = reactor.spawnProcess(protocol, twistd, args, env=env)
        self.addCleanup(os.kill, proc.pid, signal.SIGKILL)
        self.addCleanup(proc.loseConnection)

        d = self._wait_for_server()
        return d

    @defer.inlineCallbacks
    def _wait_for_server(self, retries=10):
        while retries:
            retries -= 1
            yield self._sleep(1)
            try:
                yield self._get('http://localhost:2525')
                break
            except Exception as e:
                if not retries:
                    raise e

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
