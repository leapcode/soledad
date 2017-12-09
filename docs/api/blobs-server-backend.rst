Blobs Server-side Backend Interface
===================================

The :ref:`blobs` functionality has the purpose of adding to Soledad the
capacity of handling binary objects efficiently. In this case, efficiency means
low use of resources (memory, cpu, and time) and storage scalability. The
choice of which data storage backend to use for Blobs affects each of these
properties in different ways.

The :ref:`blobs-backend-interface` is provided so that Soledad Server is
agnostic of which data backend is used for Blobs storage. In order to add a new
backend, one needs to:

* implement a backend according to the :ref:`IBlobsBackend <blobs-backend-interface>` interface,
* register the new handler in the Twisted-based ``BlobsResource``, and
* instantiate the Twisted-based ``BlobsResource`` using the new handler.

.. _blobs-backend-interface:

``IBlobsBackend`` Interface
---------------------------

.. autoclass:: leap.soledad.server.interfaces.IBlobsBackend
   :members:
   :undoc-members:
   :show-inheritance:
