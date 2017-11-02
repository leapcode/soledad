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

Server-side
-----------

In the server, attachments are stored as :ref:`blobs`. See
:ref:`blobs-http-api` for more information on how to interact with the server
using HTTP.

The :ref:`IBlobsBackend <i-blobs-backend>` interface is provided, so in the
future there can be different ways to store attachments in the server side
(think of a third-party storage, for example). Currently, the
:ref:`filesystem-backend` is the only one that implements that interface.

Client-side
-----------

In the client, attachments are relations between JSON documents and blobs.

See :ref:`client-side-attachment-api` for reference.

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
