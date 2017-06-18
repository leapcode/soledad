# -*- coding: utf-8 -*-
# _document.py
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
Public interfaces for adding extra client features to the generic
SoledadDocument.
"""

import weakref
import uuid

from twisted.internet import defer

from zope.interface import Interface
from zope.interface import implementer

from leap.soledad.common.document import SoledadDocument


class IDocumentWithAttachment(Interface):
    """
    A document that can have an attachment.
    """

    def set_store(self, store):
        """
        Set the store used by this file to manage attachments.

        :param store: The store used to manage attachments.
        :type store: Soledad
        """

    def put_attachment(self, fd):
        """
        Attach data to this document.

        Add the attachment to local storage, enqueue for upload.

        The document content will be updated with a pointer to the attachment,
        but the document has to be manually put in the database to reflect
        modifications.

        :param fd: A file-like object whose content will be attached to this
                   document.
        :type fd: file-like

        :return: A deferred which fires when the attachment has been added to
                 local storage.
        :rtype: Deferred
        """

    def get_attachment(self):
        """
        Return the data attached to this document.

        If document content contains a pointer to the attachment, try to get
        the attachment from local storage and, if not found, from remote
        storage.

        :return: A deferred which fires with a file like-object whose content
                 is the attachment of this document, or None if nothing is
                 attached.
        :rtype: Deferred
        """

    def delete_attachment(self):
        """
        Delete the attachment of this document.

        The pointer to the attachment will be removed from the document
        content, but the document has to be manually put in the database to
        reflect modifications.

        :return: A deferred which fires when the attachment has been deleted
                 from local storage.
        :rtype: Deferred
        """

    def get_attachment_state(self):
        """
        Return the state of the attachment of this document.

        The state is a member of AttachmentStates and is of one of NONE,
        LOCAL, REMOTE or SYNCED.

        :return: A deferred which fires with The state of the attachment of
                 this document.
        :rtype: Deferred
        """

    def is_dirty(self):
        """
        Return whether this document's content differs from the contents stored
        in local database.

        :return: A deferred which fires with True or False, depending on
                 whether this document is dirty or not.
        :rtype: Deferred
        """

    def upload_attachment(self):
        """
        Upload this document's attachment.

        :return: A deferred which fires with the state of the attachment after
                 it's been uploaded, or NONE if there's no attachment for this
                 document.
        :rtype: Deferred
        """

    def download_attachment(self):
        """
        Download this document's attachment.

        :return: A deferred which fires with the state of the attachment after
                 it's been downloaded, or NONE if there's no attachment for
                 this document.
        :rtype: Deferred
        """


class BlobDoc(object):

    # TODO probably not needed, but convenient for testing for now.

    def __init__(self, content, blob_id):

        self.blob_id = blob_id
        self.is_blob = True
        self.blob_fd = content
        if blob_id is None:
            blob_id = uuid.uuid4().get_hex()
        self.blob_id = blob_id


class AttachmentStates(object):
    NONE = 0
    LOCAL = 1
    REMOTE = 2
    SYNCED = 4


@implementer(IDocumentWithAttachment)
class Document(SoledadDocument):

    def __init__(self, doc_id=None, rev=None, json='{}', has_conflicts=False,
                 syncable=True, store=None):
        SoledadDocument.__init__(self, doc_id=doc_id, rev=rev, json=json,
                                 has_conflicts=has_conflicts,
                                 syncable=syncable)
        self.set_store(store)

    #
    # properties
    #

    @property
    def _manager(self):
        if not self.store or not hasattr(self.store, 'blobmanager'):
            raise Exception('No blob manager found to manage attachments.')
        return self.store.blobmanager

    @property
    def _blob_id(self):
        if self.content and 'blob_id' in self.content:
            return self.content['blob_id']
        return None

    def get_store(self):
        return self._store() if self._store else None

    def set_store(self, store):
        self._store = weakref.ref(store) if store else None

    store = property(get_store, set_store)

    #
    # attachment api
    #

    def put_attachment(self, fd):
        # add pointer to content
        blob_id = self._blob_id or str(uuid.uuid4())
        if not self.content:
            self.content = {}
        self.content['blob_id'] = blob_id
        # put using manager
        blob = BlobDoc(fd, blob_id)
        fd.seek(0, 2)
        size = fd.tell()
        fd.seek(0)
        return self._manager.put(blob, size)

    def get_attachment(self):
        if not self._blob_id:
            return defer.succeed(None)
        return self._manager.get(self._blob_id)

    def delete_attachment(self):
        raise NotImplementedError

    @defer.inlineCallbacks
    def get_attachment_state(self):
        state = AttachmentStates.NONE

        if not self._blob_id:
            defer.returnValue(state)

        local_list = yield self._manager.local_list()
        if self._blob_id in local_list:
            state |= AttachmentStates.LOCAL

        remote_list = yield self._manager.remote_list()
        if self._blob_id in remote_list:
            state |= AttachmentStates.REMOTE

        defer.returnValue(state)

    @defer.inlineCallbacks
    def is_dirty(self):
        stored = yield self.store.get_doc(self.doc_id)
        if stored.content != self.content:
            defer.returnValue(True)
        defer.returnValue(False)

    @defer.inlineCallbacks
    def upload_attachment(self):
        if not self._blob_id:
            defer.returnValue(AttachmentStates.NONE)

        fd = yield self._manager.get_blob(self._blob_id)
        # TODO: turn following method into a public one
        yield self._manager._encrypt_and_upload(self._blob_id, fd)
        defer.returnValue(self.get_attachment_state())

    @defer.inlineCallbacks
    def download_attachment(self):
        if not self._blob_id:
            defer.returnValue(None)
        yield self.get_attachment()
        defer.returnValue(self.get_attachment_state())
