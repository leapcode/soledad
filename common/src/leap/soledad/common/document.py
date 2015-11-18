# -*- coding: utf-8 -*-
# document.py
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
A Soledad Document is an u1db.Document with lasers.
"""


from u1db import Document


#
# SoledadDocument
#

class SoledadDocument(Document):

    """
    Encryptable and syncable document.

    LEAP Documents can be flagged as syncable or not, so the replicas
    might not sync every document.
    """

    def __init__(self, doc_id=None, rev=None, json='{}', has_conflicts=False,
                 syncable=True):
        """
        Container for handling an encryptable document.

        @param doc_id: The unique document identifier.
        @type doc_id: str
        @param rev: The revision identifier of the document.
        @type rev: str
        @param json: The JSON string for this document.
        @type json: str
        @param has_conflicts: Boolean indicating if this document has conflicts
        @type has_conflicts: bool
        @param syncable: Should this document be synced with remote replicas?
        @type syncable: bool
        """
        Document.__init__(self, doc_id, rev, json, has_conflicts)
        self._syncable = syncable

    def _get_syncable(self):
        """
        Return whether this document is syncable.

        @return: Is this document syncable?
        @rtype: bool
        """
        return self._syncable

    def _set_syncable(self, syncable=True):
        """
        Determine if this document should be synced with remote replicas.

        @param syncable: Should this document be synced with remote replicas?
        @type syncable: bool
        """
        self._syncable = syncable

    syncable = property(
        _get_syncable,
        _set_syncable,
        doc="Determine if document should be synced with server."
    )

    def _get_rev(self):
        """
        Get the document revision.

        Returning the revision as string solves the following exception in
        Twisted web:
            exceptions.TypeError: Can only pass-through bytes on Python 2

        @return: The document revision.
        @rtype: str
        """
        if self._rev is None:
            return None
        return str(self._rev)

    def _set_rev(self, rev):
        """
        Set document revision.

        @param rev: The new document revision.
        @type rev: bytes
        """
        self._rev = rev

    rev = property(
        _get_rev,
        _set_rev,
        doc="Wrapper to ensure `doc.rev` is always returned as bytes.")


class ServerDocument(SoledadDocument):
    """
    This is the document used by server to hold conflicts and transactions
    on a database.

    The goal is to ensure an atomic and consistent update of the database.
    """

    def __init__(self, doc_id=None, rev=None, json='{}', has_conflicts=False):
        """
        Container for handling a document that stored on server.

        :param doc_id: The unique document identifier.
        :type doc_id: str
        :param rev: The revision identifier of the document.
        :type rev: str
        :param json: The JSON string for this document.
        :type json: str
        :param has_conflicts: Boolean indicating if this document has conflicts
        :type has_conflicts: bool
        """
        SoledadDocument.__init__(self, doc_id, rev, json, has_conflicts)
        self._conflicts = None

    def get_conflicts(self):
        """
        Get the conflicted versions of the document.

        :return: The conflicted versions of the document.
        :rtype: [ServerDocument]
        """
        return self._conflicts or []

    def set_conflicts(self, conflicts):
        """
        Set the conflicted versions of the document.

        :param conflicts: The conflicted versions of the document.
        :type conflicts: list
        """
        self._conflicts = conflicts
        self.has_conflicts = len(self._conflicts) > 0

    def add_conflict(self, doc):
        """
        Add a conflict to this document.

        :param doc: The conflicted version to be added.
        :type doc: Document
        """
        if self._conflicts is None:
            raise Exception("Fetch conflicts first!")
        self._conflicts.append(doc)
        self.has_conflicts = len(self._conflicts) > 0

    def delete_conflicts(self, conflict_revs):
        """
        Delete conflicted versions of this document.

        :param conflict_revs: The conflicted revisions to be deleted.
        :type conflict_revs: [str]
        """
        if self._conflicts is None:
            raise Exception("Fetch conflicts first!")
        self._conflicts = filter(
            lambda doc: doc.rev not in conflict_revs,
            self._conflicts)
        self.has_conflicts = len(self._conflicts) > 0
