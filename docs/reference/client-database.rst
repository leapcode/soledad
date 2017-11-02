.. _client-databases:

Client-side databases
=====================

These are some important information about Soledad's client-side databases:

- Soledad Client uses `SQLCipher <https://www.zetetic.net/sqlcipher/>`_ for
  storing data.
- :ref:`Documents <document-encryption>` and :ref:`blobs <blobs>` are stored in
  different databases protected with the same symmetric key.
- The symmetric key used to unlock databases is chosen randomly and is stored
  encrypted by the user's passphrase (see :ref:`storage-secrets` for more details).

The database files currently used in the client-side are:

- ``<user_id>.db``: The database for JSON documents storage.
- ``<user_id>_blobs.db``: The database for storage of blobs.

Depending on how local databases are configured, you may also find files with
the same names of the above but ending in ``-wal`` and ``-shm``, which
correspond to SQLCipher's `Write-Ahead Logging
<http://www.sqlite.org/wal.html>`_ implementation.
