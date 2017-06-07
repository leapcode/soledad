Document attachments
====================

.. contents:: Contents:
   :local:

Reasoning
---------

The type of a Soledad document's content is `JSON <http://www.json.org/>`_,
which is good for efficient lookup and indexing. On the other hand, this is
particularly bad for storing larger amounts of binary data, because:

* the only way to store data in JSON is as unicode string, and this uses more
  space than what is actually needed for binary data storage.

* upon synchronization, the content of a Soledad document needs to be
  completelly transferred and decrypted for the document to be available for
  use.

Document attachments were introduced as a means to efficiently store large
payloads of binary data while avoiding the need to wait for their transfer to
have access to the documents' contents.

Client-side
-----------

In the client, attachments are stored as (SQLite) BLOBs in a separate SQLCipher
database. Encryption of data before it's sent to the server is the same used
for Soledad documents' content during usual synchronization process (AES-256
GCM mode).

Usage example
^^^^^^^^^^^^^

The attachments API is currently available in the `Document` class, and the
document needs to know about the store to be able to manage attachments. When
you create a new document with soledad, that document will already know about
the store that created it, and can put/get/delete an attachment:

.. code-block:: python

    from twisted.internet.defer import inlineCallbacks

    @inlineCallbacks
    def attachment_example(soledad):
        doc = yield soledad.create_doc({})

        state = yield doc.get_attachment_state()
        dirty = yield doc.is_dirty()
        assert state == AttachmentStates.NONE
        assert dirty == False

        yield doc.put_attachment(open('hackers.txt'))
        state = yield doc.get_attachment_state()
        dirty = yield doc.is_dirty()
        assert state | AttachmentState.LOCAL
        assert dirty == True

        yield soledad.put_doc(doc)
        dirty = yield doc.is_dirty()
        assert dirty == False

        yield doc.upload_attachment()
        state = yield doc.get_attachment_state()
        assert state | AttachmentState.REMOTE
        assert state == AttachmentState.SYNCED

        fd = yield doc.get_attachment()
        assert fd.read() == open('hackers.txt').read()

API
^^^

.. autoclass:: leap.soledad.client._document.AttachmentStates
   :members:
   :undoc-members:

.. autointerface:: leap.soledad.client._document.IDocumentWithAttachment
   :members:
   :undoc-members:

Server-side
-----------

In the server, a simple REST API is served by a `Twisted Resource
<https://twistedmatrix.com/documents/current/api/twisted.web.resource.Resource.html>`_
and attachments are stored in the filesystem as they come in without
modification.

A token is used to allow listing, getting, putting and deleting attachments. It
has to be added as an HTTP auth header, as in::

    Authorization: Token <base64-encoded uuid:token>

The :ref:`IBlobsBackend <i-blobs-backend>` interface is provided, so in the
future there can be different ways to store attachments in the server side
(think of a third-party storage, for example). Currently, the
:ref:`FilesystemBlobsBackend <filesystem-blobs-backend>` is the only backend
that implements that interface.

Some characteristics of the :ref:`FilesystemBlobsBackend
<filesystem-blobs-backend>` are:

* Configurable storage path.
* Quota support.
* Username, blob_id and user storage directory sanitization.

Usage example
^^^^^^^^^^^^^

These are the possible ways to interact with the attachments REST API on the
server side:

===========  ================  ======== ==================
HTTP Method  URL               Content  Possible responses
===========  ================  ======== ==================
GET          /user_id          -        200
GET          /user_id/blob_id  -        200, 404
PUT          /user_id/blob_id  The BLOB 200, 409, 507
DELETE       /user_id/blob_id  -        200
===========  ================  ======== ==================

API
^^^

.. _i-blobs-backend:

.. autoclass:: leap.soledad.server.interfaces.IBlobsBackend
   :members:
   :undoc-members:

.. _filesystem-blobs-backend:

.. autoclass:: leap.soledad.server._blobs.FilesystemBlobsBackend
   :members:
   :undoc-members:
