# -*- coding: utf-8 -*-
# auth.py
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
Methods for token-based authentication.
"""


def set_token_credentials(self, address, token):
    self._creds = {'token': (address, token)}


def _sign_request(self, method, url_query, params):
    if 'token' in self._creds:
        address, token = self._creds['token']
        auth = '%s:%s' % (address, token)
        return [('Authorization', 'Token %s' % auth.encode('base64'))]
