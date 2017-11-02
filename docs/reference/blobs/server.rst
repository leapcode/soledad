Server-side blobs
=================

The server-side implementation of blobs provides HTTP APIs for data storage
using a filesystem backend.

HTTP APIs
---------

Soledad Server provides two different REST APIs for interacting with blobs:

* A *public* :ref:`blobs-http-api`, providing the *Blobs* service for Soledad
  Client (i.e. actual users of the infrastructure).

* A *local* :ref:`incoming-http-api`, providing the delivery part of the
  :ref:`incoming-box` service, currently used for the MX mail delivery.

Authentication is handled differently for each of the endpoints, see
:ref:`authentication` for more details.

.. _filesystem-backend:

Filesystem backend
------------------

On the server side, all blobs are currently stored in the filesystem, under
``/var/lib/soledad/blobs`` by default. Blobs are split in subdirectories
according to the user's uuid, the namespace, and the 1, 3 and 6-letter prefixes
of the blobs uuid to prevent too many files in the same directory.  A second
file with the extension ``.flags`` stores the flags for a blob.

As an example, a ``PUT`` request to ``/blobs/some-user-id/some-blob-id``
would result in the following filesystem structure in the server::

    /var/lib/soledad/blobs
    └── some-user-id
        └── default
            └── s
                └── som
                    └── some-b
                        ├── some-blob-id 
                        └── some-blob-id.flags
