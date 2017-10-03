.. _client-databases:

Client-side databases
=====================

Soledad Client uses `SQLCipher <https://www.zetetic.net/sqlcipher/>`_ for
storing data. The symmetric key used to unlock databases is chosen randomly and
stored encrypted with the user's passphrase (see :ref:`storage-secrets` for
more details).

:ref:`Documents <document-encryption>` and :ref:`blobs <blobs>` are stored in
different databases protected with the same symmetric secret.
