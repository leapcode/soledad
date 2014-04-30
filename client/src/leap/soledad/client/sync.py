# -*- coding: utf-8 -*-
# sync.py
# Copyright (C) 2014 LEAP
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
Sync infrastructure that can be interrupted and recovered.
"""

import json


from u1db import errors
from u1db.sync import Synchronizer as U1DBSynchronizer


class ClientSyncState(object):
    """
    The state of the current sync session, as stored on the client.
    """

    _private_attrs = [
        '_db',
    ]

    _public_attrs = {
        'target_replica_uid': None,
        'target_gen': None,
        'target_trans_id': None,
        'target_my_gen': None,
        'target_my_trans_id': None,
        'target_last_known_gen': None,
        'target_last_known_trans_id': None,
        'my_gen': None,
        'changes': None,
        'sent': 0,
        'received': 0,
    }

    @property
    def _public_attr_keys(self):
        return [k for k in self._public_attrs]

    def __init__(self, db=None):
        """
        Initialize the client sync state.

        :param db: The database where to fetch/store the sync state.
        :type db: SQLCipherDatabase
        """
        self._db = db
        self._init_state()

    def __setattr__(self, attr, val):
        """
        Prevent setting arbitrary attributes.

        :param attr: The attribute name.
        :type attr: str
        :param val: The value to be set.
        :type val: anything
        """
        if attr not in self._public_attr_keys + self._private_attrs:
            raise Exception
        object.__setattr__(self, attr, val)

    def _init_state(self):
        """
        Initialize current sync state, potentially fetching sync info stored
        in database.
        """
        # set local default attributes
        for attr in self._public_attr_keys:
            setattr(self, attr, self._public_attrs[attr])
        # fetch info from stored sync state
        sync_state = None
        if self._db is not None:
            sync_state = self._db.sync_state
        if sync_state is not None:
            for attr in self._public_attr_keys:
                setattr(self, attr, sync_state[attr])

    def save(self):
        """
        Save the current sync state in the database.
        """
        sync_state = {}
        for attr in self._public_attr_keys:
            sync_state[attr] = getattr(self, attr)
        if self._db is not None:
            self._db.sync_state = sync_state

    def clear(self):
        """
        Clear the sync state info data.
        """
        if self._db is not None:
            self._db.sync_state = None
        self._init_state()

    def has_stored_info(self):
        """
        Return wether there is any sync state info stored on the database.

        :return: Wether there's any sync state info store on db.
        :rtype: bool
        """
        return self._db is not None and self._db.sync_state is not None

    def __str__(self):
        ', '.join(['%s: %s' % (k, getattr(self, k)) for k in self._public_attr_keys])

class Synchronizer(U1DBSynchronizer):
    """
    Collect the state around synchronizing 2 U1DB replicas.

    Modified to allow for interrupting the synchronization process.
    """

    def stop(self):
        """
        Stop the current sync in progress.
        """
        self.sync_target.stop()

    def sync(self, autocreate=False):
        """
        Synchronize documents between source and target.

        :param autocreate: Wether the target replica should be created or not.
        :type autocreate: bool
        """
        sync_target = self.sync_target

        # recover current sync state from source database
        sync_state = ClientSyncState(self.source)
        self.target_replica_uid = sync_state.target_replica_uid
        target_gen = sync_state.target_gen
        target_trans_id = sync_state.target_trans_id
        target_my_gen = sync_state.target_my_gen
        target_my_trans_id = sync_state.target_my_trans_id
        target_last_known_gen = sync_state.target_last_known_gen
        target_last_known_trans_id = \
            sync_state.target_last_known_trans_id
        my_gen = sync_state.my_gen
        changes = sync_state.changes
        sent = sync_state.sent
        received = sync_state.received

        # get target identifier, its current generation,
        # and its last-seen database generation for this source
        ensure_callback = None
        if not sync_state.has_stored_info():
            try:
                (self.target_replica_uid, target_gen, target_trans_id,
                 target_my_gen, target_my_trans_id) = \
                    sync_target.get_sync_info(self.source._replica_uid)
            except errors.DatabaseDoesNotExist:
                if not autocreate:
                    raise
                # will try to ask sync_exchange() to create the db
                self.target_replica_uid = None
                target_gen, target_trans_id = 0, ''
                target_my_gen, target_my_trans_id = 0, ''

        # make sure we'll have access to target replica uid once it exists
        if self.target_replica_uid is None:

            def ensure_callback(replica_uid):
                self.target_replica_uid = replica_uid

        # make sure we're not syncing one replica with itself
        if self.target_replica_uid == self.source._replica_uid:
            raise errors.InvalidReplicaUID

        # validate the info the target has about the source replica
        self.source.validate_gen_and_trans_id(
            target_my_gen, target_my_trans_id)

        # what's changed since that generation and this current gen
        if not sync_state.has_stored_info():
            my_gen, _, changes = self.source.whats_changed(target_my_gen)

        # get source last-seen database generation for the target
        if not sync_state.has_stored_info():
            if self.target_replica_uid is None:
                target_last_known_gen, target_last_known_trans_id = 0, ''
            else:
                target_last_known_gen, target_last_known_trans_id = \
                    self.source._get_replica_gen_and_trans_id(
                        self.target_replica_uid)

        # validate transaction ids
        if not changes and target_last_known_gen == target_gen:
            if target_trans_id != target_last_known_trans_id:
                raise errors.InvalidTransactionId
            return my_gen

        # prepare to send all the changed docs
        changed_doc_ids = [doc_id for doc_id, _, _ in changes]
        docs_to_send = self.source.get_docs(
            changed_doc_ids, check_for_conflicts=False, include_deleted=True)
        docs_by_generation = []
        idx = 0
        for doc in docs_to_send:
            _, gen, trans = changes[idx]
            docs_by_generation.append((doc, gen, trans))
            idx += 1
        # store current sync state info
        if not sync_state.has_stored_info():
            sync_state.target_replica_uid = self.target_replica_uid
            sync_state.target_gen = target_gen
            sync_state.target_trans_id = target_trans_id
            sync_state.target_my_gen = target_my_gen
            sync_state.target_my_trans_id = target_my_trans_id
            sync_state.my_gen = my_gen
            sync_state.changes = changes
            sync_state.target_last_known_trans_id = \
                target_last_known_trans_id
            sync_state.target_last_known_gen = target_last_known_gen
            sync_state.sent = sent = 0
            sync_state.received = received = 0

        # exchange documents and try to insert the returned ones with
        # the target, return target synced-up-to gen.
        #
        # The sync_exchange method may be interrupted, in which case it will
        # return a tuple of Nones.
        new_gen, new_trans_id = sync_target.sync_exchange(
            docs_by_generation, self.source._replica_uid,
            target_last_known_gen, target_last_known_trans_id,
            self._insert_doc_from_target, ensure_callback=ensure_callback,
            sync_state=sync_state)

        # save sync state info if the sync was interrupted
        if new_gen is None and new_trans_id is None:
            sync_state.save()
            return my_gen

        # sync exchange was succesfull, remove sync state info from source
        sync_state.clear()

        # record target synced-up-to generation including applying what we sent
        self.source._set_replica_gen_and_trans_id(
            self.target_replica_uid, new_gen, new_trans_id)
        # if gapless record current reached generation with target
        self._record_sync_info_with_the_target(my_gen)

        return my_gen
