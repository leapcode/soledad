Soledad API
===========

.. contents::
   :local:

.. _client-side-code-api:

Client-side code API
--------------------

.. autoclass:: leap.soledad.client.Soledad
    :members:
    :undoc-members:

.. _client-side-attachments-api:

Client-side attachments API
---------------------------

.. autoclass:: leap.soledad.client._document.AttachmentStates
   :members:
   :undoc-members:

.. autointerface:: leap.soledad.client._document.IDocumentWithAttachment
   :members:
   :undoc-members:


.. _server-side-attachments-rest-api:

Server-side attachments REST API
--------------------------------

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

Server-side attachments code API
--------------------------------

.. _i-blobs-backend:

.. autoclass:: leap.soledad.server.interfaces.IBlobsBackend
   :members:
   :undoc-members:

.. _filesystem-blobs-backend:

.. autoclass:: leap.soledad.server._blobs.FilesystemBlobsBackend
   :members:
   :undoc-members:
