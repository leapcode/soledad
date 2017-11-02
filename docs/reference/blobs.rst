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

.. toctree::
   :maxdepth: 2

   blobs/server
   blobs/client
