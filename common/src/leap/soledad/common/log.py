# -*- coding: utf-8 -*-
# log.py
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
This module centralizes logging facilities and allows for different behaviours,
as using the python logging module instead of twisted logger, and to print logs
to stdout, mainly for development purposes.
"""


import os
import sys
import time

from twisted.logger import Logger
from twisted.logger import textFileLogObserver
from twisted.logger import LogLevel
from twisted.logger import InvalidLogLevelError
from twisted.python.failure import Failure


# What follows is a patched class to correctly log namespace and level when
# using the default formatter and --syslog option in twistd. This seems to be a
# known bug but it has not been reported to upstream yet.

class SyslogLogger(Logger):

    def emit(self, level, format=None, **kwargs):
        if level not in LogLevel.iterconstants():
            self.failure(
                "Got invalid log level {invalidLevel!r} in {logger}.emit().",
                Failure(InvalidLogLevelError(level)),
                invalidLevel=level,
                logger=self,
            )
            return

        event = kwargs
        event.update(
            log_logger=self, log_level=level, log_namespace=self.namespace,
            log_source=self.source, log_format=format, log_time=time.time(),
        )

        # ---------------------------------8<---------------------------------
        # this is a workaround for the mess between twisted's legacy log system
        # and twistd's --syslog option.
        event["system"] = "%s#%s" % (self.namespace, level.name)
        # ---------------------------------8<---------------------------------

        if "log_trace" in event:
            event["log_trace"].append((self, self.observer))

        self.observer(event)


def getLogger(*args, **kwargs):

    if os.environ.get('SOLEDAD_USE_PYTHON_LOGGING'):
        import logging
        return logging.getLogger(__name__)

    if os.environ.get('SOLEDAD_LOG_TO_STDOUT'):
        kwargs({'observer': textFileLogObserver(sys.stdout)})

    return SyslogLogger(*args, **kwargs)


__all__ = ['getLogger']
