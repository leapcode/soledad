# -*- coding: utf-8 -*-
# config.py
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
Management of configuration sources for Soledad.
"""

import os
import logging


from xdg import BaseDirectory
from leap.common.config.baseconfig import BaseConfig


logger = logging.getLogger(name=__name__)


PREFIX = os.path.join(
    BaseDirectory.xdg_config_home,
    'leap', 'soledad')


soledad_config_spec = {
    'description': 'sample soledad config',
    'type': 'object',
    'properties': {
        'secret_path': {
            'type': unicode,
            'default': PREFIX + '/secret.gpg',
            'required': True,
        },
        'local_db_path': {
            #'type': unicode,
            'default': PREFIX + '/soledad.u1db',
            'required': True,
        },
        'shared_db_url': {
            'type': unicode,
            'default': 'http://provider/soledad/shared',
            'required': True,  # should this be True?
        },
    }
}


class SoledadConfig(BaseConfig):

    def _get_spec(self):
        """
        Returns the spec object for the specific configuration
        """
        return soledad_config_spec

    def get_secret_path(self):
        return self._safe_get_value("secret_path")

    def get_local_db_path(self):
        return self._safe_get_value("local_db_path")

    def get_shared_db_url(self):
        return self._safe_get_value("shared_db_url")


if __name__ == "__main__":
    logger = logging.getLogger(name='leap')
    logger.setLevel(logging.DEBUG)
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        '%(asctime)s '
        '- %(name)s - %(levelname)s - %(message)s')
    console.setFormatter(formatter)
    logger.addHandler(console)

    soledadconfig = SoledadConfig()

    try:
        soledadconfig.get_local_db_path()
    except Exception as e:
        assert isinstance(e, AssertionError), "Expected an assert"
        print "Safe value getting is working"
