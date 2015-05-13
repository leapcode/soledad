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
Soledad synchronization utilities.

Extend u1db Synchronizer with the ability to:

    * Postpone the update of the known replica uid until all the decryption of
      the incoming messages has been processed.

    * Be interrupted and recovered.
"""
import logging
import traceback
from threading import Lock

from u1db import errors
from u1db.sync import Synchronizer


logger = logging.getLogger(__name__)


class SoledadSynchronizer(Synchronizer):
    """
    Collect the state around synchronizing 2 U1DB replicas.

    Synchronization is bi-directional, in that new items in the source are sent
    to the target, and new items in the target are returned to the source.
    However, it still recognizes that one side is initiating the request. Also,
    at the moment, conflicts are only created in the source.

    Also modified to allow for interrupting the synchronization process.
    """

    # TODO can delegate the syncing to the api object, living in the reactor
    # thread, and use a simple flag.
    syncing_lock = Lock()

    def stop(self):
        """
        Stop the current sync in progress.
        """
        self.sync_target.stop()

    def sync(self, autocreate=False, defer_decryption=True):
        """
        Synchronize documents between source and target.

        Differently from u1db `Synchronizer.sync` method, this one allows to
        pass a `defer_decryption` flag that will postpone the last
        step in the synchronization dance, namely, the setting of the last
        known generation and transaction id for a given remote replica.

        This is done to allow the ongoing parallel decryption of the incoming
        docs to proceed without `InvalidGeneration` conflicts.

        :param autocreate: Whether the target replica should be created or not.
        :type autocreate: bool
        :param defer_decryption: Whether to defer the decryption process using
                                 the intermediate database. If False,
                                 decryption will be done inline.
        :type defer_decryption: bool
        """
        self.syncing_lock.acquire()
        try:
            return self._sync(autocreate=autocreate,
                              defer_decryption=defer_decryption)
        except Exception:
            # we want this exception to reach either SQLCipherU1DBSync.sync or
            # the Solead api object itself, so it is poperly handled and/or
            # logged...
            raise
        finally:
            # ... but we also want to release the syncing lock so this
            # Synchronizer may be reused later.
            self.release_syncing_lock()

    def _sync(self, autocreate=False, defer_decryption=True):
        """
        Helper function, called from the main `sync` method.
        See `sync` docstring.
        """
        sync_target = self.sync_target

        # get target identifier, its current generation,
        # and its last-seen database generation for this source
        ensure_callback = None
        try:
            (self.target_replica_uid, target_gen, target_trans_id,
             target_my_gen, target_my_trans_id) = \
                sync_target.get_sync_info(self.source._replica_uid)
        except errors.DatabaseDoesNotExist:
            if not autocreate:
                raise
            # will try to ask sync_exchange() to create the db
            self.target_replica_uid = None
            target_gen, target_trans_id = (0, '')
            target_my_gen, target_my_trans_id = (0, '')

        logger.debug(
            "Soledad target sync info:\n"
            "  target replica uid: %s\n"
            "  target generation: %d\n"
            "  target trans id: %s\n"
            "  target my gen: %d\n"
            "  target my trans_id: %s\n"
            "  source replica_uid: %s\n"
            % (self.target_replica_uid, target_gen, target_trans_id,
               target_my_gen, target_my_trans_id, self.source._replica_uid))

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
        my_gen, _, changes = self.source.whats_changed(target_my_gen)
        logger.debug("Soledad sync: there are %d documents to send."
                     % len(changes))

        # get source last-seen database generation for the target
        if self.target_replica_uid is None:
            target_last_known_gen, target_last_known_trans_id = 0, ''
        else:
            target_last_known_gen, target_last_known_trans_id = \
                self.source._get_replica_gen_and_trans_id(
                    self.target_replica_uid)
        logger.debug(
            "Soledad source sync info:\n"
            "  source target gen: %d\n"
            "  source target trans_id: %s"
            % (target_last_known_gen, target_last_known_trans_id))

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

        # exchange documents and try to insert the returned ones with
        # the target, return target synced-up-to gen.
        #
        # The sync_exchange method may be interrupted, in which case it will
        # return a tuple of Nones.
        try:
            new_gen, new_trans_id = sync_target.sync_exchange(
                docs_by_generation, self.source._replica_uid,
                target_last_known_gen, target_last_known_trans_id,
                self._insert_doc_from_target, ensure_callback=ensure_callback,
                defer_decryption=defer_decryption)
            logger.debug(
                "Soledad source sync info after sync exchange:\n"
                "  source target gen: %d\n"
                "  source target trans_id: %s"
                % (new_gen, new_trans_id))
            info = {
                "target_replica_uid": self.target_replica_uid,
                "new_gen": new_gen,
                "new_trans_id": new_trans_id,
                "my_gen": my_gen
            }
            self._syncing_info = info
            self.complete_sync()
        except Exception as e:
            logger.error("Soledad sync error: %s" % str(e))
            logger.error(traceback.format_exc())
            sync_target.stop()
        finally:
            sync_target.close()

        return my_gen

    def complete_sync(self):
        """
        Last stage of the synchronization:
            (a) record last known generation and transaction uid for the remote
            replica, and
            (b) make target aware of our current reached generation.
        """
        logger.debug("Completing deferred last step in SYNC...")

        # record target synced-up-to generation including applying what we
        # sent
        info = self._syncing_info
        self.source._set_replica_gen_and_trans_id(
            info["target_replica_uid"], info["new_gen"], info["new_trans_id"])

        # if gapless record current reached generation with target
        self._record_sync_info_with_the_target(info["my_gen"])

    @property
    def syncing(self):
        """
        Return True if a sync is ongoing, False otherwise.
        :rtype: bool
        """
        # XXX FIXME  we need some mechanism for timeout: should cleanup and
        # release if something in the syncdb-decrypt goes wrong. we could keep
        # track of the release date and cleanup unrealistic sync entries after
        # some time.

        # TODO use cancellable deferreds instead
        locked = self.syncing_lock.locked()
        return locked

    def release_syncing_lock(self):
        """
        Release syncing lock if it's locked.
        """
        if self.syncing_lock.locked():
            self.syncing_lock.release()

    def close(self):
        """
        Close sync target pool of workers.
        """
        self.release_syncing_lock()
        self.sync_target.close()

    def __del__(self):
        """
        Cleanup: release lock.
        """
        self.release_syncing_lock()
