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


"""
Soledad routines common to client and server.
"""


from hashlib import sha256


#
# Global constants
#


SHARED_DB_NAME = 'shared'
SHARED_DB_LOCK_DOC_ID_PREFIX = 'lock-'
USER_DB_PREFIX = 'user-'


#
# Global functions
#

# we want to use leap.common.check.leap_assert in case it is available,
# because it also logs in a way other parts of leap can access log messages.

try:
    from leap.common.check import leap_assert as soledad_assert

except ImportError:

    def soledad_assert(condition, message):
        """
        Asserts the condition and displays the message if that's not
        met.

        @param condition: condition to check
        @type condition: bool
        @param message: message to display if the condition isn't met
        @type message: str
        """
        assert condition, message

try:
    from leap.common.check import leap_assert_type as soledad_assert_type

except ImportError:

    def soledad_assert_type(var, expectedType):
        """
        Helper assert check for a variable's expected type

        @param var: variable to check
        @type var: any
        @param expectedType: type to check agains
        @type expectedType: type
        """
        soledad_assert(isinstance(var, expectedType),
                       "Expected type %r instead of %r" %
                       (expectedType, type(var)))


from ._version import get_versions
__version__ = get_versions()['version']
del get_versions
