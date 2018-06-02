.. _storage-secrets:

Storage secrets
===============

All data stored locally and remotelly is encrypted using "storage secrets".

Storage secrets are backed up in the provider
---------------------------------------------

Storage secrets are currently backed up in the provider (encrypted with the
user's passphrase) for the case where the user looses or resets her device (see
:ref:`shared-database` for more information). There are plans to make this
feature optional, allowing for less trust in the provider while increasing the
responsibility of the user.

Because of that, whenever Soledad is initialized for the first time, it checks
for existence of storage secrets in local storage. If these are not found, then
it checks if there is an available backup in the provider. These steps are
currently mandatory because Soledad needs to make sure it will have any
previously used secrets in order to encrypt/decrypt previously synchronized
data accordingly. If the device is offline during the first initialization,
Soledad will raise an exception and fail to initialize.

For testing purposes, it is possible to initialize Soledad passing a `None`
value as server url, but offline mode is currently not supported and may lead
to unintended consequences.

If the user looses her passphrase, there is currently no way of recovering her
data.

Format of the secrets file
--------------------------

When created for the first time, storage secrets are themselves encrypted using
a key derived from the user’s passphrase, and saved locally on disk. The
encrypted secrets are stored in a local file in the user's in a JSON structure
that looks like this::

    {
        'version': 2,
        'kdf': 'scrypt',
        'kdf_salt': <base64 encoded salt>,
        'kdf_length': <the length of the derived key>,
        'cipher': <a code indicating the cipher used for encryption>,
        'length': <the length of the plaintext>,
        'iv': <the initialization vector>,
        'secrets': <base64 encoding of ciphertext>,
    }

When a client application first wants to use Soledad, it must provide the
user’s password to unlock the storage secrets.

Currently, the same storage secrets are shared among all devices with access to
a particular user's Soledad database.
