# -*- coding: utf-8 -*-
# command.py
# Copyright (C) 2015 LEAP
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
Utility to sanitize and run shell commands.
"""


import subprocess


def exec_validated_cmd(cmd, argument, validator=None):
    """
    Executes cmd, validating argument with a validator function.

    :param cmd: command.
    :type dbname: str
    :param argument: argument.
    :type argument: str
    :param validator: optional function to validate argument
    :type validator: function

    :return: exit code and stdout or stderr (if code != 0)
    :rtype: (int, str)
    """
    if validator and not validator(argument):
        return 1, "invalid argument"
    command = cmd.split(' ')
    command.append(argument)
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
    except OSError, e:
        return 1, e
    (out, err) = process.communicate()
    code = process.wait()
    if code is not 0:
        return code, err
    else:
        return code, out
