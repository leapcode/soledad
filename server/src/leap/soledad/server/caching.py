# -*- coding: utf-8 -*-
# caching.py
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
Server side caching. Using beaker for now.
"""
from beaker.cache import CacheManager


def setup_caching():
    _cache_manager = CacheManager(type='memory')
    return _cache_manager


_cache_manager = setup_caching()


def get_cache_for(key, expire=3600):
    return _cache_manager.get_cache(key, expire=expire)
