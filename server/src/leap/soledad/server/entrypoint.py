# -*- coding: utf-8 -*-
# entrypoint.py
# Copyright (C) 2016 LEAP
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
The entrypoint for Soledad server.
"""
from twisted.internet import reactor

from ._config import get_config
from ._wsgi import init_couch_state
from .session import SoledadSession


# load configuration from file
conf = get_config


class SoledadEntrypoint(SoledadSession):

    def __init__(self):
        SoledadSession.__init__(self, conf)


# see the comments in application.py recarding why couch state has to be
# initialized when the reactor is running
reactor.callWhenRunning(init_couch_state, conf['soledad-server'])
