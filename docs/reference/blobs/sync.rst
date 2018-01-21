.. _blobs-sync:

Blobs Synchronization
=====================

Because blobs are immutable, synchronization is much simpler than the
JSON-based :ref:`document-sync`. The synchronization process is as follows:

1. The client asks the server for a list of Blobs and compares it with the local list.
2. A local list is updated with pending downloads and uploads.
3. Downloads and uploads are triggered.

Immutability brings some characteristics to the blobs system:

- There's no need for storage of versions or revisions.
- Updating is not possible (you would need to delete and recreate a blob).

Server-side storage format
--------------------------

When a blob is uploaded by a client, its contents are encrypted with
a symmetric secret prior to being sent to the server. When a blob is
downloaded, its contents are decrypted accordingly. See
:ref:`client-encryption` for more details.

In the server-side, a preamble is prepended to the encrypted content. The
preamble is an encoded struct that contains the following metadata:

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


Client-side synchronization details
-----------------------------------

Synchronization status
~~~~~~~~~~~~~~~~~~~~~~

In the client-side, each blob has an associated synchronization status, which
can be one of:

- ``SYNCED``: The blob exists both in this client and in the server.
- ``PENDING_UPLOAD``: The blob was inserted locally, but has not yet been uploaded.
- ``PENDING_DOWNLOAD``: The blob exists in the server, but has not yet been downloaded.
- ``FAILED_DOWNLOAD``: A download attempt has been made but the content is corrupted for some reason.

Concurrency limits
~~~~~~~~~~~~~~~~~~

In order to increase the speed of synchronization on the client-size,
concurrent database operations and transfers to the server are allowed. Despite
that, to prevent indiscriminated use of client resources (cpu, memory,
bandwith), concurrenty limits are set both for database operations and data
transfer.

Transfer retries
~~~~~~~~~~~~~~~~

When a blob is queded for download or upload, it will stay in that queue until
the transfer has been successful or until there has been an unrecoverable
transfer error. Currently, the only unrecoverable transfer error is a failed
verification of the blob tag (i.e. a failed MAC verification).

Successive failed transfer attempts of the same blob are separated by an
increasing time interval to minimize competition for resources used by other
concurrent transfer attempts. The interaval starts at 10 seconds and increases
to 20, 30, 40, 50, and finally 60 seconds. All further retries will be
separated by a 60 seconds time interval.

Streaming
~~~~~~~~~

In order to optimize synchronization of small payloads, the blobs
synchronization system provides a special ``stream/`` endpoint (see
:ref:`blobs-http-api`). Using that endpoint, the client is able to transfer
multiple blobs in a single stream of data. This method improves resources
usage, specially in scenarios in which blobs are so small that setting up one
connection for each blob would generate a noticeable overhead.

Downstream
``````````

During download, the client provides a list of blobs by POSTing a JSON
formatted list of blob identifiers. The server then starts producing a stream
of data in which each of the requested blobs is written in a format that is the
concatenation of the following:

* The blob size in hex (padded to 8 bytes).
* A base64-encoded AES-GCM 16 byte tag.
* A space (to act as a separator).
* The encrypted contents of the blob.

Upstream
````````

During upload, the client will produce a stream of blobs in the following
format:

* First line: a JSON encoded list of tuples with each blob identifier and size.
  Note that the size is the size of the encrypted blob, which matches exactly
  what the client is sending on the stream.
* Second line: all encrypted blobs contents, for each blob in the list above.
