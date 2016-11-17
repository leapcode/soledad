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

from twisted.logger import Logger
from twisted.logger import textFileLogObserver


def getLogger(*args, **kwargs):

    if os.environ.get('SOLEDAD_USE_PYTHON_LOGGING'):
        import logging
        return logging.getLogger(__name__)

    if os.environ.get('SOLEDAD_LOG_TO_STDOUT'):
        kwargs({'observer': textFileLogObserver(sys.stdout)})

    return Logger(*args, **kwargs)


__all__ = ['getLogger']
