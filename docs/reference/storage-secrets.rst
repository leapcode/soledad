.. _storage-secrets:

Storage secrets
===============

Soledad randomly generates secrets that are used to derive encryption keys for
protecting all data that is stored in the server and in the local storage.
These secrets are themselves encrypted using a key derived from the user’s
passphrase, and saved locally on disk.

The encrypted secrets are stored in a local file in the user's in a JSON
structure that looks like this::

    encrypted = {
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
user’s password to unlock the storage secrets. Currently, the storage secrets
are shared among all devices with access to a particular user's Soledad
database.

The storage secrets are currently backed up in the provider (encrypted with the
user's passphrase) for the case where the user looses or resets her device (see
:ref:`shared-database` for more information). There are plans to make this
feature optional, allowing for less trust in the provider while increasing the
responsibility of the user.

If the user looses her passphrase, there is currently no way of recovering her
data.
