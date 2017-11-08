# -*- coding: utf-8 -*-
# launcher.py
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
Soledad Server launcher.
"""
import argparse
import os
import sys

from twisted.scripts.twistd import run

from leap.soledad import server, __version__


STANDALONE = getattr(sys, 'frozen', False)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--version', action='store_true',
                        help='Print the program version.')
    return parser.parse_args()


def here(module=None):
    if STANDALONE:
        # we are running in a |PyInstaller| bundle
        return sys._MEIPASS
    else:
        if module:
            return os.path.dirname(module.__file__)
        else:
            return os.path.dirname(__file__)


def run_server():

    # maybe print version and exit
    args = parse_args()
    if args.version:
        print __version__
        return

    # launch soledad server using twistd
    tac = os.path.join(here(server), 'server.tac')
    args = [
        '--nodaemon',
        '--pidfile=',
        '--syslog',
        '--prefix=soledad-server',
        '--python=%s' % tac,
    ]
    sys.argv[1:] = args
    run()


if __name__ == '__main__':
    run_server()
