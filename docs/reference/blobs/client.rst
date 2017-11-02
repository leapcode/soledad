Client-side blobs
=================

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
