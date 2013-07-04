# -*- coding: utf-8 -*-
# leap_backend.py 
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
This file exists to provide backwards compatibility with code that uses
Soledad before the refactor that removed the leap_backend module.
"""


import logging
import warnings


from leap.soledad import document
from leap.soledad import target


logger = logging.getLogger(name=__name__)


def warn(oldclass, newclass):
    """
    Warns about deprecation of C{oldclass}, which must be substituted by
    C{newclass}.

    @param oldclass: The class that is deprecated.
    @type oldclass: type
    @param newclass: The class that should be used instead.
    @type newclass: type
    """
    message = \
        "%s is deprecated and will be removed soon. Please use %s instead." \
        % (str(oldclass), str(newclass))
    print message
    logger.warning(message)
    warnings.warn(message, DeprecationWarning, stacklevel=2)


class LeapDocument(document.SoledadDocument):
    """
    This class exists to provide backwards compatibility with code that still
    uses C{leap.soledad.backends.leap_backend.LeapDocument}.
    """

    def __init__(self, *args, **kwargs):
        warn(self.__class__, document.SoledadDocument)
        document.SoledadDocument.__init__(self, *args, **kwargs)


class EncryptionSchemes(target.EncryptionSchemes):
    """
    This class exists to provide backwards compatibility with code that still
    uses C{leap.soledad.backends.leap_backend.EncryptionSchemes}.
    """

    def __init__(self, *args, **kwargs):
        warn(self.__class__, target.EncryptionSchemes)
        target.EncryptionSchemes.__init__(self, *args, **kwargs)
