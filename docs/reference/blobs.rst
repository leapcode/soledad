.. _blobs:

Blobs
=====

The first versions of Soledad used to store all data as JSON documents, which
means that binary data was also being treated as strings. This has many
drawbacks, as increased memory usage and difficulties to do transfer and crypto
in a proper binary pipeline.

Starting with version **0.10.0**, Soledad now has a proper blob infrastructure
that decouples payloads from metadata both in storage and in the
synchronization process.


Server-side
-----------

Soledad Server provides two different REST APIs for interacting with blobs:

* A public **HTTP Blobs API**, providing the *Blobs* service for Soledad Client
  (i.e. actual users of the infrastructure).

* A local **HTTP Incoming Box API**, providing the delivery part of the
  :ref:`incoming-box` service, currently used for the MX mail delivery.

Authentication is handled differently for each of the endpoints, see
:ref:`authentication` for more details.


.. _http-blobs-api:

HTTP Blobs API
~~~~~~~~~~~~~~

The public endpoint provides the following REST API for interacting with the
*Blobs* service:

=========================== ========== ================================= ============================================
path                        method     action                            accepted query string fields
=========================== ========== ================================= ============================================
``/blobs/{uuid}``           ``GET``    Get a list of blobs. filtered by  ``namespace``, ``filter_flag``, ``order_by``
                                       a flag.
``/blobs/{uuid}/{blob_id}`` ``GET``    Get the contents of a blob.       ``namespace``
``/blobs/{uuid}/{blob_id}`` ``PUT``    Create a blob. The content of the ``namespace``
                                       blob should be sent in the body
                                       of the request.
``/blobs/{uuid}/{blob_id}`` ``POST``   Set the flags for a blob. A list  ``namespace``
                                       of flags should be sent in the
                                       body of the request.
``/blobs/{uuid}/{blob_id}`` ``DELETE`` Delete a blob.                    ``namespace``
=========================== ========== ================================= ============================================

The Blobs service supports *namespaces*. All requests can be modified by the
``namespace`` query string parameter, and the results will be restricted to
a certain namespace. When no namespace explicitelly given, the ``default``
namespace is used.

When listing blobs, the results can be filtered by flag and/or ordered by date
using the ``filter_flag`` and ``order_by`` query string parameters. The
possible values for ``order_by`` are ``date`` or ``+date`` for increasing
order, or ``-date`` for decreasing order.


HTTP Incoming Box API
~~~~~~~~~~~~~~~~~~~~~

The local endpoint provides the following REST API for interacting with the
:ref:`incoming-box` service.

============================== ========== =================================
path                           method     action
============================== ========== =================================
``/incoming/{uuid}/{blob_id}`` ``PUT``    Create an incoming blob. The content of the blob should be sent in the body of the request.
============================== ========== =================================

All blobs created using this API are inserted under the namespace ``MX`` and
flagged as ``PENDING``.


.. _filesystem-backend:

Filesystem backend
~~~~~~~~~~~~~~~~~~

On the server side, all blobs are currently stored in the filesystem, under
``/var/lib/soledad/blobs`` by default. Blobs are split in subdirectories
according to the user's uuid, the namespace, and the 3-letter and 6-letter
prefixes of the blobs uuid to prevent too many files in the same directory.
A second file with the extension ``.flags`` stores the flags for a blob.

As an example, a ``PUT`` request to
``/incoming/68625dcb68dab741adf29c7159ccff96/c56da69b25a9a11ec2f408a559ccffc6``
would result in the following::

    /var/lib/soledad/blobs
    └── 68625dcb68dab741adf29c7159ccff96
        └── MX
            └── c56
                └── c56da6
                    ├── c56da69b25a9a11ec2f408a559ccffc6
                    └── c56da69b25a9a11ec2f408a559ccffc6.flags


Client-side
-----------

On the client-side, blobs can be managed using the BlobManager API.  The
BlobManager is responsible for managing storage of blobs both in local and
remote storages

All data is stored locally in the ``blobs`` table of a SQLCipher database
called ``{uuid}_blobs.db`` that lies in the same directory as the Soledad
Client's JSON documents database. Both databases are encrypted with the same
symmetric secret. All actions performed locally are mirrored remotelly using
the :ref:`http-blobs-api`.

The BlobManager supports *namespaces* and *flags* and can list local and remote
blobs, possibly filtering by flags and ordering by date (increasingly or
decreasingly). It has helper methods to send or fetch all missing blobs, thus
aiding in synchronization of local and remote data.

When uploading, the content of the blob is encrypted with a symmetric secret
prior to being sent to the server. When downloading, the content of the blob is
decrypted accordingly.
