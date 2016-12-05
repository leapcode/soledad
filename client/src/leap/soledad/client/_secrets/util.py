# -*- coding:utf-8 -*-
# _secrets/util.py
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


from leap.soledad.client import events


class SecretsError(Exception):
    pass


def emit(verb):
    def _decorator(method):
        def _decorated(self, *args, **kwargs):

            # emit starting event
            user_data = self._user_data
            name = 'SOLEDAD_' + verb.upper() + '_KEYS'
            event = getattr(events, name)
            events.emit_async(event, user_data)

            # run the method
            result = method(self, *args, **kwargs)

            # emit a finished event
            name = 'SOLEDAD_DONE_' + verb.upper() + '_KEYS'
            event = getattr(events, name)
            events.emit_async(event, user_data)

            return result
        return _decorated
    return _decorator
