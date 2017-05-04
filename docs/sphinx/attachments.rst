Document Attachments
====================

.. contents:: Contents:
   :local:

The content of a Soledad document is assumed to be JSON. This is particularly
bad for storing larger amounts of binary data, because:

* the only way to store data in JSON is as unicode string, and this uses more
  space than needed for binary data storage.

* the process of synchronization of Soledad documents depends on completing the
  transfer and decryption of the content of all new/updated documents before
  synchronized documents are available for use.

Document attachments were introduced as a means to store large payloads of
binary data and have them be synchronized separate from the usual Soledad
document synchronization process.

Example
-------

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

Implementation
--------------

The current implementation of document attachments store data in a separate
SQLCipher database in the client (using SQLite's BLOB type) and in the
filesystem in the server. Encryption of data before it's sent to the server is
the same used by normal Soledad synchronization process (AES-256 GCM mode).

Document attachment API
-----------------------

.. autoclass:: leap.soledad.client._document.AttachmentStates
   :members:
   :undoc-members:

.. autointerface:: leap.soledad.client._document.IDocumentWithAttachment
   :members:
   :undoc-members:
