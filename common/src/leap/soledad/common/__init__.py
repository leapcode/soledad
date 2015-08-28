# -*- coding: utf-8 -*-
# __init__.py
# Copyright (C) 2013 LEAP
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

from leap.common.check import leap_assert as soledad_assert
from leap.common.check import leap_assert_type as soledad_assert_type

from ._version import get_versions

"""
Soledad routines common to client and server.
"""


#
# Global constants
#

SHARED_DB_NAME = 'shared'
SHARED_DB_LOCK_DOC_ID_PREFIX = 'lock-'
USER_DB_PREFIX = 'user-'


#
# Global functions
#

__version__ = get_versions()['version']
del get_versions


__all__ = [
    "soledad_assert",
    "soledad_assert_type",
    "__version__",
]
