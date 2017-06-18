# -*- coding: utf-8 -*-
# _recovery_code.py
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

import os
import binascii

from leap.soledad.common.log import getLogger

logger = getLogger(__name__)


class RecoveryCode(object):

    # When we turn this string to hex, it will double in size
    code_length = 6

    def generate(self):
        logger.info("generating new recovery code...")
        return binascii.hexlify(os.urandom(self.code_length))
