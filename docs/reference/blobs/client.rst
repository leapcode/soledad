Client-side blobs
=================

Data storage
------------

On the client-side, blobs can be managed using the ``BlobManager`` API, which
is responsible for managing storage of blobs both in local and remote storages.
See :ref:`blobmanager-api` and :ref:`blobs-sync-api` for information on the
client-side API.

All data is stored locally in the ``blobs`` table of a SQLCipher database
called ``{uuid}_blobs.db`` that lies in the same directory as the Soledad
Client's JSON documents database (see :ref:`client-databases`). All actions
performed locally are mirrored remotelly using the :ref:`blobs-http-api`.

Client-side encryption and authentication
-----------------------------------------

When uploading, the content of the blob is encrypted with a symmetric secret
prior to being sent to the server. When downloading, the content of the blob is
decrypted accordingly. See :ref:`client-encryption` for more details.

When a blob is uploaded by a client, a preamble is created and prepended to the
encrypted content. The preamble is an encoded struct that contains the
following metadata:

- A 2 character **magic hexadecimal number** for easy identification of a Blob
  data type. Currently, the value used for the magic number is: ``\x13\x37``.
- The **cryptographic scheme** used for encryption. Currently, the only valid
  schemes are ``symkey`` and ``external``.
- The **encryption method** used. Currently, the only valid methods are
  ``aes_256_gcm`` and ``pgp``.
- The **initialization vector**.
- The **blob_id**.
- The **revision**, which is a fixed value (``ImmutableRev``) in the case of
  blobs.
- The **size** of the blob.

The final format of a blob that is uploaded to the server is the following:

- The URL-safe base64-encoded **preamble** (see above).
- A space to act as a **separator**.
- The URL-safe base64-encoded concatenated **encrypted data and MAC tag**.

Namespaces
----------

The Blobs API supports **namespaces** so that applications can store and fetch
blobs without interfering in each another. Namespaces are also used to
implement the server-side :ref:`incoming-http-api`, used for mail delivery. All
methods that deal with blobs storage, transfer and flagging provide
a `namespace` parameter. If no namespace is given, the value `default` is used.
See :ref:`blobmanager-api` for information on how to use namespaces.

Remote flags
------------

In order to allow clients to control the processing of blobs that are delivered
by external applications, the Blobs API has the concept of **remote flags**.
The client can get and set the following flags for Blobs that reside in the
server: ``PENDING``, ``PROCESSING``, ``PROCESSED``, and ``FAILED``. See
:ref:`blobmanager-api` for more information on how to use flags.

Remote listing
--------------

The client can obtain a list of blobs in the server side so it can compare with
its own local list and queue up blobs for download and upload. The remote
listing can be ordered by *upload date* and filtered by *namespace* and *flag*.
The listing can also only return the number of matches instead of the whole
content. See :ref:`blobmanager-api` for more information on how to use remote
listing.
