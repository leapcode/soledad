Blobs Synchronization
=====================

Because blobs are immutable, synchronization is much simpler than the
JSON-based :ref:`document-sync`. The synchronization process is as follows:

1. The client asks the server for a list of Blobs and compares it with the local list.
2. A local list is updated with pending blobs download and upload.
3. Downloads and uploads are triggered.

Immutability brings some characteristics to the blobs system:

- There's no need for storage of versions or revisions.
- Updating is not possible (you would need to delete and recreate a blob).

Synchronization status
----------------------

In the client-side, each has an associated synchronization status, which can be
one of:

- `SYNCED`: The blob exists both in this client and in the server.
- `PENDING_UPLOAD`: The blob was inserted locally, but has not yet been uploaded.
- `PENDING_DOWNLOAD`: The blob exists in the server, but has not yet been downloaded.
- `FAILED_DOWNLOAD`: A download attempt has been made but the content is corrupted for some reason.

Concurrency limits
------------------

In order to increase the speed of synchronization on the client-size,
concurrent database operations and transfers to the server are allowed. Despite
that, to prevent indiscriminated use or client resources (cpu, memory,
bandwith), concurrenty limits are set both for database operations and for data
transfer.

Transfer retries
----------------

When a blob is queded for download or upload, it will stay in that queue until
the transfer has been successful or until there has been an unrecoverable
transfer error. Currently, the only unrecoverable transfer error is a failed
verification of the blob tag (i.e. a failed MAC verification).

Successive transfer attempts have an increasing delay between them, to minimize
competition for resources used by other concurrent transfer attempts. The delay
starts with 10 seconds and increases to 20, 30, 40, 50, and finally 60 seconds
on each new failed attempt. The delay for a new retry then stays at 60 seconds
for new attempts.
