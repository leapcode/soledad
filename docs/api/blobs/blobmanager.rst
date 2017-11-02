.. _blobmanager-api:

Blobs creation, retrieval, deletion and flagging
================================================

The ``BlobManager`` class is responsible for blobs creation, retrieval,
deletion, flagging and synchronizing. For better code organization, the methods
related to synchronization are implemented separatelly in a superclass (see
:ref:`blobs-sync-api`).

.. autoclass:: leap.soledad.client._db.blobs.BlobManager
   :members:
   :special-members: __init__
   :undoc-members:
   :show-inheritance:
