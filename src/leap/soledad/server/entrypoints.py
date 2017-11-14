# -*- coding: utf-8 -*-
# entrypoints.py
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
Entrypoints for the Soledad server.
"""
from twisted.internet import reactor
from twisted.python import threadpool

from leap.soledad.common.log import getLogger

from .auth import localPortal, publicPortal
from .session import SoledadSession


log = getLogger(__name__)


class UsersEntrypoint(SoledadSession):

    def __init__(self):
        pool = threadpool.ThreadPool(name='wsgi')
        reactor.callWhenRunning(pool.start)
        reactor.addSystemEventTrigger('after', 'shutdown', pool.stop)
        portal = publicPortal(sync_pool=pool)
        SoledadSession.__init__(self, portal)


class ServicesEntrypoint(SoledadSession):

    def __init__(self):
        portal = localPortal()
        SoledadSession.__init__(self, portal)
