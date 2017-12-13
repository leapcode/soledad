# -*- coding: utf-8 -*-
# __init__.py
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
Represents flags that can be used on blobs.
"""
from collections import namedtuple
ACCEPTED_FLAGS = ['PENDING', 'PROCESSING', 'PROCESSED', 'FAILED']
Flags = namedtuple('Flags', ' '.join(ACCEPTED_FLAGS))(*ACCEPTED_FLAGS)


class InvalidFlag(Exception):
    """
    Raised when a flag that is not accepted is used.
    """
