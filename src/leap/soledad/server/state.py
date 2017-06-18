# -*- coding: utf-8 -*-
# state.py
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
Server side synchronization infrastructure.
"""
from leap.soledad.server import caching


class ServerSyncState(object):
    """
    The state of one sync session, as stored on backend server.

    On server side, the ongoing syncs metadata is maintained in
    a caching layer.
    """

    def __init__(self, source_replica_uid, sync_id):
        """
        Initialize the sync state object.

        :param sync_id: The id of current sync
        :type sync_id: str
        :param source_replica_uid: The source replica uid
        :type source_replica_uid: str
        """
        self._source_replica_uid = source_replica_uid
        self._sync_id = sync_id
        caching_key = source_replica_uid + sync_id
        self._storage = caching.get_cache_for(caching_key)

    def _put_dict_info(self, key, value):
        """
        Put some information about the sync state.

        :param key: The key for the info to be put.
        :type key: str
        :param value: The value for the info to be put.
        :type value: str
        """
        if key not in self._storage:
            self._storage[key] = []
        info_list = self._storage.get(key)
        info_list.append(value)
        self._storage[key] = info_list

    def put_seen_id(self, seen_id, gen):
        """
        Put one seen id on the sync state.

        :param seen_id: The doc_id of a document seen during sync.
        :type seen_id: str
        :param gen: The corresponding db generation.
        :type gen: int
        """
        self._put_dict_info(
            'seen_id',
            (seen_id, gen))

    def seen_ids(self):
        """
        Return all document ids seen during the sync.

        :return: A dict with doc ids seen during the sync.
        :rtype: dict
        """
        if 'seen_id' in self._storage:
            seen_ids = self._storage.get('seen_id')
        else:
            seen_ids = []
        return dict(seen_ids)

    def put_changes_to_return(self, gen, trans_id, changes_to_return):
        """
        Put the calculated changes to return in the backend sync state.

        :param gen: The target database generation that will be synced.
        :type gen: int
        :param trans_id: The target database transaction id that will be
                         synced.
        :type trans_id: str
        :param changes_to_return: A list of tuples with the changes to be
                                  returned during the sync process.
        :type changes_to_return: list
        """
        self._put_dict_info(
            'changes_to_return',
            {
                'gen': gen,
                'trans_id': trans_id,
                'changes_to_return': changes_to_return,
            }
        )

    def sync_info(self):
        """
        Return information about the current sync state.

        :return: The generation and transaction id of the target database
                 which will be synced, and the number of documents to return,
                 or a tuple of Nones if those have not already been sent to
                 server.
        :rtype: tuple
        """
        gen = trans_id = number_of_changes = None
        if 'changes_to_return' in self._storage:
            info = self._storage.get('changes_to_return')[0]
            gen = info['gen']
            trans_id = info['trans_id']
            number_of_changes = len(info['changes_to_return'])
        return gen, trans_id, number_of_changes

    def next_change_to_return(self, received):
        """
        Return the next change to be returned to the source syncing replica.

        :param received: How many documents the source replica has already
                         received during the current sync process.
        :type received: int
        """
        gen = trans_id = next_change_to_return = None
        if 'changes_to_return' in self._storage:
            info = self._storage.get('changes_to_return')[0]
            gen = info['gen']
            trans_id = info['trans_id']
            if received < len(info['changes_to_return']):
                next_change_to_return = (info['changes_to_return'][received])
        return gen, trans_id, next_change_to_return
