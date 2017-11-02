Blobs Server-side HTTP API
==========================

Soledad Server provides two different REST APIs for interacting with blobs:

* A *public* :ref:`blobs-http-api`, providing the *Blobs* service for Soledad
  Client (i.e. actual users of the infrastructure).

* A *local* :ref:`incoming-http-api`, providing the delivery part of the
  :ref:`incoming-box` service, currently used for the MX mail delivery.

Authentication is handled differently for each of the endpoints, see
:ref:`authentication` for more details.

.. _blobs-http-api:

Public Blobs HTTP API
---------------------

The *public endpoint* provides the following REST API for interacting with the
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

.. _incoming-http-api:

Local Incoming Box HTTP API
---------------------------

The *local endpoint* provides the following REST API for interacting with the
:ref:`incoming-box` service.

============================== ========== =================================
path                           method     action
============================== ========== =================================
``/incoming/{uuid}/{blob_id}`` ``PUT``    Create an incoming blob. The content of the blob should be sent in the body of the request.
============================== ========== =================================

All blobs created using this API are inserted under the namespace ``MX`` and
flagged as ``PENDING``.
