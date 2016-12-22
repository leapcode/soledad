# -*- coding: utf-8 -*-
# secrets.py
# Copyright (C) 2014 LEAP
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.


"""
Soledad secrets handling.
"""


import os
import scrypt
import binascii
import errno
import json

from hashlib import sha256

from leap.soledad.common import soledad_assert
from leap.soledad.common import soledad_assert_type
from leap.soledad.common import document
from leap.soledad.common.log import getLogger
from leap.soledad.client import events
from leap.soledad.client import _crypto


logger = getLogger(__name__)


#
# Exceptions
#


class SecretsException(Exception):

    """
    Generic exception type raised by this module.
    """


class NoStorageSecret(SecretsException):

    """
    Raised when trying to use a storage secret but none is available.
    """
    pass


class PassphraseTooShort(SecretsException):

    """
    Raised when trying to change the passphrase but the provided passphrase is
    too short.
    """


class BootstrapSequenceError(SecretsException):

    """
    Raised when an attempt to generate a secret and store it in a recovery
    document on server failed.
    """


#
# Secrets handler
#


class SoledadSecrets(object):

    """
    Soledad secrets handler.

    The first C{self.REMOTE_STORAGE_SECRET_LENGTH} bytes of the storage
    secret are used for remote storage encryption. We use the next
    C{self.LOCAL_STORAGE_SECRET} bytes to derive a key for local storage.
    From these bytes, the first C{self.SALT_LENGTH} bytes are used as the
    salt and the rest as the password for the scrypt hashing.
    """

    LOCAL_STORAGE_SECRET_LENGTH = 512
    """
    The length, in bytes, of the secret used to derive a passphrase for the
    SQLCipher database.
    """

    REMOTE_STORAGE_SECRET_LENGTH = 512
    """
    The length, in bytes, of the secret used to derive an encryption key for
    remote storage.
    """

    SALT_LENGTH = 64
    """
    The length, in bytes, of the salt used to derive the key for the storage
    secret encryption.
    """

    GEN_SECRET_LENGTH = LOCAL_STORAGE_SECRET_LENGTH \
        + REMOTE_STORAGE_SECRET_LENGTH \
        + SALT_LENGTH  # for sync db
    """
    The length, in bytes, of the secret to be generated. This includes local
    and remote secrets, and the salt for deriving the sync db secret.
    """

    MINIMUM_PASSPHRASE_LENGTH = 6
    """
    The minimum length, in bytes, for a passphrase. The passphrase length is
    only checked when the user changes her passphrase, not when she
    instantiates Soledad.
    """

    SEPARATOR = ":"
    """
    A separator used for storing the encryption initial value prepended to the
    ciphertext.
    """

    UUID_KEY = 'uuid'
    STORAGE_SECRETS_KEY = 'storage_secrets'
    ACTIVE_SECRET_KEY = 'active_secret'
    SECRET_KEY = 'secret'
    CIPHER_KEY = 'cipher'
    LENGTH_KEY = 'length'
    KDF_KEY = 'kdf'
    KDF_SALT_KEY = 'kdf_salt'
    KDF_LENGTH_KEY = 'kdf_length'
    KDF_SCRYPT = 'scrypt'
    CIPHER_AES256 = 'aes256'  # deprecated, AES-CTR
    CIPHER_AES256_GCM = _crypto.ENC_METHOD.aes_256_gcm
    RECOVERY_DOC_VERSION_KEY = 'version'
    RECOVERY_DOC_VERSION = 1
    """
    Keys used to access storage secrets in recovery documents.
    """

    def __init__(self, uuid, passphrase, secrets_path, shared_db, userid=None):
        """
        Initialize the secrets manager.

        :param uuid: User's unique id.
        :type uuid: str
        :param passphrase: The passphrase for locking and unlocking encryption
                           secrets for local and remote storage.
        :type passphrase: unicode
        :param secrets_path: Path for storing encrypted key used for
                             symmetric encryption.
        :type secrets_path: str
        :param shared_db: The shared database that stores user secrets.
        :type shared_db: leap.soledad.client.shared_db.SoledadSharedDatabase
        """
        self._uuid = uuid
        self._userid = userid
        self._passphrase = passphrase
        self._secrets_path = secrets_path
        self._shared_db = shared_db
        self._secrets = {}
        self._secret_id = None

    def bootstrap(self):
        """
        Bootstrap secrets.

        Soledad secrets bootstrap is the following sequence of stages:

        * stage 1 - local secret loading:
            - if secrets exist locally, load them.
        * stage 2 - remote secret loading:
            - else, if secrets exist in server, download them.
        * stage 3 - secret generation:
            - else, generate a new secret and store in server.

        This method decides which bootstrap stages have already been performed
        and performs the missing ones in order.

        :raise BootstrapSequenceError: Raised when the secret generation and
            storage on server sequence has failed for some reason.
        """
        # STAGE 1 - verify if secrets exist locally
        try:
            logger.info("trying to load secrets from local storage...")
            version = self._load_secrets_from_local_file()
            # eventually migrate local and remote stored documents from old
            # format version
            if version < self.RECOVERY_DOC_VERSION:
                self._store_secrets()
                self._upload_crypto_secrets()
            logger.info("found secrets in local storage")
            return

        except NoStorageSecret:
            logger.info("could not find secrets in local storage")

        # STAGE 2 - there are no secrets in local storage and this is the
        #           first time we are running soledad with the specified
        #           secrets_path. Try to fetch encrypted secrets from
        #           server.
        try:
            logger.info('trying to fetch secrets from remote storage...')
            version = self._download_crypto_secrets()
            self._store_secrets()
            # eventually migrate remote stored document from old format
            # version
            if version < self.RECOVERY_DOC_VERSION:
                self._upload_crypto_secrets()
            logger.info('found secrets in remote storage.')
            return
        except NoStorageSecret:
            logger.info("could not find secrets in remote storage.")

        # STAGE 3 - there are no secrets in server also, so we want to
        #           generate the secrets and store them in the remote
        #           db.
        logger.info("generating secrets...")
        self._gen_crypto_secrets()
        logger.info("uploading secrets...")
        self._upload_crypto_secrets()

    def _has_secret(self):
        """
        Return whether there is a storage secret available for use or not.

        :return: Whether there's a storage secret for symmetric encryption.
        :rtype: bool
        """
        return self.storage_secret is not None

    def _maybe_set_active_secret(self, active_secret):
        """
        If no secret_id is already set, choose the passed active secret, or
        just choose first secret available if none.
        """
        if not self._secret_id:
            if not active_secret:
                active_secret = self._secrets.items()[0][0]
            self.set_secret_id(active_secret)

    def _load_secrets_from_local_file(self):
        """
        Load storage secrets from local file.

        :return version: The version of the locally stored recovery document.

        :raise NoStorageSecret: Raised if there are no secrets available in
                                local storage.
        """
        # check if secrets file exists and we can read it
        if not os.path.isfile(self._secrets_path):
            raise NoStorageSecret

        # read storage secrets from file
        content = None
        with open(self._secrets_path, 'r') as f:
            content = json.loads(f.read())
        _, active_secret, version = self._import_recovery_document(content)

        self._maybe_set_active_secret(active_secret)

        return version

    def _download_crypto_secrets(self):
        """
        Download crypto secrets.

        :return version: The version of the remotelly stored recovery document.

        :raise NoStorageSecret: Raised if there are no secrets available in
                                remote storage.
        """
        doc = None
        if self._shared_db.syncable:
            doc = self._get_secrets_from_shared_db()

        if doc is None:
            raise NoStorageSecret

        _, active_secret, version = self._import_recovery_document(doc.content)
        self._maybe_set_active_secret(active_secret)

        return version

    def _gen_crypto_secrets(self):
        """
        Generate the crypto secrets.
        """
        logger.info('no cryptographic secrets found, creating new secrets...')
        secret_id = self._gen_secret()
        self.set_secret_id(secret_id)

    def _upload_crypto_secrets(self):
        """
        Send crypto secrets to shared db.

        :raises BootstrapSequenceError: Raised when unable to store secrets in
                                        shared database.
        """
        if self._shared_db.syncable:
            try:
                self._put_secrets_in_shared_db()
            except Exception as ex:
                # storing generated secret in shared db failed for
                # some reason, so we erase the generated secret and
                # raise.
                try:
                    os.unlink(self._secrets_path)
                except OSError as e:
                    if e.errno != errno.ENOENT:
                        # no such file or directory
                        logger.exception(e)
                logger.exception(ex)
                raise BootstrapSequenceError(
                    'Could not store generated secret in the shared '
                    'database, bailing out...')

    #
    # Shared DB related methods
    #

    def _shared_db_doc_id(self):
        """
        Calculate the doc_id of the document in the shared db that stores key
        material.

        :return: the hash
        :rtype: str
        """
        return sha256(
            '%s%s' %
            (self._passphrase_as_string(), self._uuid)).hexdigest()

    def _export_recovery_document(self, cipher=None):
        """
        Export the storage secrets.

        Current format of recovery document has the following structure:

            {
                'storage_secrets': {
                    '<storage_secret id>': {
                        'cipher': 'aes256',
                        'length': <secret length>,
                        'secret': '<encrypted storage_secret>',
                    },
                },
                'active_secret': '<secret_id>',
                'version': '<recovery document format version>',
            }

        Note that multiple storage secrets might be stored in one recovery
        document.

        :param cipher: (Optional) The ciper to use. Defaults to AES256
        :type cipher: str

        :return: The recovery document.
        :rtype: dict
        """
        # encrypt secrets
        encrypted_secrets = {}
        for secret_id in self._secrets:
            encrypted_secrets[secret_id] = self._encrypt_storage_secret(
                self._secrets[secret_id], doc_cipher=cipher)
        # create the recovery document
        data = {
            self.STORAGE_SECRETS_KEY: encrypted_secrets,
            self.ACTIVE_SECRET_KEY: self._secret_id,
            self.RECOVERY_DOC_VERSION_KEY: self.RECOVERY_DOC_VERSION,
        }
        return data

    def _import_recovery_document(self, data):
        """
        Import storage secrets for symmetric encryption from a recovery
        document.

        Note that this method does not store the imported data on disk. For
        that, use C{self._store_secrets()}.

        :param data: The recovery document.
        :type data: dict

        :return: A tuple containing the number of imported secrets, the
                 secret_id of the last active secret, and the recovery
                 document format version.
        :rtype: (int, str, int)
        """
        soledad_assert(self.STORAGE_SECRETS_KEY in data)
        version = data.get(self.RECOVERY_DOC_VERSION_KEY, 1)
        meth = getattr(self, '_import_recovery_document_version_%d' % version)
        secret_count, active_secret = meth(data)
        return secret_count, active_secret, version

    def _import_recovery_document_version_1(self, data):
        """
        Import storage secrets for symmetric encryption from a recovery
        document with format version 1.

        Version 1 of recovery document has the following structure:

            {
                'storage_secrets': {
                    '<storage_secret id>': {
                        'cipher': 'aes256',
                        'length': <secret length>,
                        'secret': '<encrypted storage_secret>',
                    },
                },
                'active_secret': '<secret_id>',
                'version': '<recovery document format version>',
            }

        :param data: The recovery document.
        :type data: dict

        :return: A tuple containing the number of imported secrets, the
                 secret_id of the last active secret, and the recovery
                 document format version.
        :rtype: (int, str, int)
        """
        # include secrets in the secret pool.
        secret_count = 0
        secrets = data[self.STORAGE_SECRETS_KEY].items()
        active_secret = None
        # XXX remove check for existence of key (included for backwards
        # compatibility)
        if self.ACTIVE_SECRET_KEY in data:
            active_secret = data[self.ACTIVE_SECRET_KEY]
        for secret_id, encrypted_secret in secrets:
            if secret_id not in self._secrets:
                try:
                    self._secrets[secret_id] = \
                        self._decrypt_storage_secret_version_1(
                            encrypted_secret)
                    secret_count += 1
                except SecretsException as e:
                    logger.error("failed to decrypt storage secret: %s"
                                 % str(e))
                    raise e
        return secret_count, active_secret

    def _get_secrets_from_shared_db(self):
        """
        Retrieve the document with encrypted key material from the shared
        database.

        :return: a document with encrypted key material in its contents
        :rtype: document.SoledadDocument
        """
        user_data = self._get_user_data()
        events.emit_async(events.SOLEDAD_DOWNLOADING_KEYS, user_data)
        db = self._shared_db
        if not db:
            logger.warn('no shared db found')
            return
        doc = db.get_doc(self._shared_db_doc_id())
        user_data = {'userid': self._userid, 'uuid': self._uuid}
        events.emit_async(events.SOLEDAD_DONE_DOWNLOADING_KEYS, user_data)
        return doc

    def _put_secrets_in_shared_db(self):
        """
        Assert local keys are the same as shared db's ones.

        Try to fetch keys from shared recovery database. If they already exist
        in the remote db, assert that that data is the same as local data.
        Otherwise, upload keys to shared recovery database.
        """
        soledad_assert(
            self._has_secret(),
            'Tried to send keys to server but they don\'t exist in local '
            'storage.')
        # try to get secrets doc from server, otherwise create it
        doc = self._get_secrets_from_shared_db()
        if doc is None:
            doc = document.SoledadDocument(
                doc_id=self._shared_db_doc_id())
        # fill doc with encrypted secrets
        doc.content = self._export_recovery_document()
        # upload secrets to server
        user_data = self._get_user_data()
        events.emit_async(events.SOLEDAD_UPLOADING_KEYS, user_data)
        db = self._shared_db
        if not db:
            logger.warn('no shared db found')
            return
        db.put_doc(doc)
        events.emit_async(events.SOLEDAD_DONE_UPLOADING_KEYS, user_data)

    #
    # Management of secret for symmetric encryption.
    #

    def _decrypt_storage_secret_version_1(self, encrypted_secret_dict):
        """
        Decrypt the storage secret.

        Storage secret is encrypted before being stored. This method decrypts
        and returns the decrypted storage secret.

        Version 1 of storage secret format has the following structure:

            '<storage_secret id>': {
                'cipher': 'aes256',
                'length': <secret length>,
                'secret': '<encrypted storage_secret>',
            },

        :param encrypted_secret_dict: The encrypted storage secret.
        :type encrypted_secret_dict:  dict

        :return: The decrypted storage secret.
        :rtype: str

        :raise SecretsException: Raised in case the decryption of the storage
                                 secret fails for some reason.
        """
        # calculate the encryption key
        if encrypted_secret_dict[self.KDF_KEY] != self.KDF_SCRYPT:
            raise SecretsException("Unknown KDF in stored secret.")
        key = scrypt.hash(
            self._passphrase_as_string(),
            # the salt is stored base64 encoded
            binascii.a2b_base64(
                encrypted_secret_dict[self.KDF_SALT_KEY]),
            buflen=32,  # we need a key with 256 bits (32 bytes).
        )
        if encrypted_secret_dict[self.KDF_LENGTH_KEY] != len(key):
            raise SecretsException("Wrong length of decryption key.")
        supported_ciphers = [self.CIPHER_AES256, self.CIPHER_AES256_GCM]
        doc_cipher = encrypted_secret_dict[self.CIPHER_KEY]
        if doc_cipher not in supported_ciphers:
            raise SecretsException("Unknown cipher in stored secret.")
        # recover the initial value and ciphertext
        iv, ciphertext = encrypted_secret_dict[self.SECRET_KEY].split(
            self.SEPARATOR, 1)
        ciphertext = binascii.a2b_base64(ciphertext)
        try:
            decrypted_secret = _crypto.decrypt_sym(
                ciphertext, key, iv, doc_cipher)
        except Exception as e:
            logger.error(e)
            raise SecretsException("Unable to decrypt secret.")
        if encrypted_secret_dict[self.LENGTH_KEY] != len(decrypted_secret):
            raise SecretsException("Wrong length of decrypted secret.")
        return decrypted_secret

    def _encrypt_storage_secret(self, decrypted_secret, doc_cipher=None):
        """
        Encrypt the storage secret.

        An encrypted secret has the following structure:

            {
                '<secret_id>': {
                        'kdf': 'scrypt',
                        'kdf_salt': '<b64 repr of salt>'
                        'kdf_length': <key length>
                        'cipher': 'aes256',
                        'length': <secret length>,
                        'secret': '<encrypted b64 repr of storage_secret>',
                }
            }

        :param decrypted_secret: The decrypted storage secret.
        :type decrypted_secret: str
        :param cipher: (Optional) The ciper to use. Defaults to AES256
        :type cipher: str

        :return: The encrypted storage secret.
        :rtype: dict
        """
        # generate random salt
        salt = os.urandom(self.SALT_LENGTH)
        # get a 256-bit key
        key = scrypt.hash(self._passphrase_as_string(), salt, buflen=32)
        doc_cipher = doc_cipher or self.CIPHER_AES256_GCM
        iv, ciphertext = _crypto.encrypt_sym(decrypted_secret, key, doc_cipher)
        ciphertext = binascii.b2a_base64(ciphertext)
        encrypted_secret_dict = {
            # leap.soledad.crypto submodule uses AES256 for symmetric
            # encryption.
            self.KDF_KEY: self.KDF_SCRYPT,
            self.KDF_SALT_KEY: binascii.b2a_base64(salt),
            self.KDF_LENGTH_KEY: len(key),
            self.CIPHER_KEY: doc_cipher,
            self.LENGTH_KEY: len(decrypted_secret),
            self.SECRET_KEY: self.SEPARATOR.join([str(iv), ciphertext])
        }
        return encrypted_secret_dict

    @property
    def storage_secret(self):
        """
        Return the storage secret.

        :return: The decrypted storage secret.
        :rtype: str
        """
        return self._secrets.get(self._secret_id)

    def set_secret_id(self, secret_id):
        """
        Define the id of the storage secret to be used.

        This method will also replace the secret in the crypto object.

        :param secret_id: The id of the storage secret to be used.
        :type secret_id: str
        """
        self._secret_id = secret_id

    def _gen_secret(self):
        """
        Generate a secret for symmetric encryption and store in a local
        encrypted file.

        This method emits the following events.signals:

            * SOLEDAD_CREATING_KEYS
            * SOLEDAD_DONE_CREATING_KEYS

        :return: The id of the generated secret.
        :rtype: str
        """
        user_data = self._get_user_data()
        events.emit_async(events.SOLEDAD_CREATING_KEYS, user_data)
        # generate random secret
        secret = os.urandom(self.GEN_SECRET_LENGTH)
        secret_id = sha256(secret).hexdigest()
        self._secrets[secret_id] = secret
        self._store_secrets()
        events.emit_async(events.SOLEDAD_DONE_CREATING_KEYS, user_data)
        return secret_id

    def _store_secrets(self):
        """
        Store secrets in C{Soledad.STORAGE_SECRETS_FILE_PATH}.
        """
        with open(self._secrets_path, 'w') as f:
            f.write(
                json.dumps(
                    self._export_recovery_document()))

    def change_passphrase(self, new_passphrase):
        """
        Change the passphrase that encrypts the storage secret.

        :param new_passphrase: The new passphrase.
        :type new_passphrase: unicode

        :raise NoStorageSecret: Raised if there's no storage secret available.
        """
        # TODO: maybe we want to add more checks to guarantee passphrase is
        # reasonable?
        soledad_assert_type(new_passphrase, unicode)
        if len(new_passphrase) < self.MINIMUM_PASSPHRASE_LENGTH:
            raise PassphraseTooShort(
                'Passphrase must be at least %d characters long!' %
                self.MINIMUM_PASSPHRASE_LENGTH)
        # ensure there's a secret for which the passphrase will be changed.
        if not self._has_secret():
            raise NoStorageSecret()
        self._passphrase = new_passphrase
        self._store_secrets()
        self._put_secrets_in_shared_db()

    #
    # Setters and getters
    #

    @property
    def secret_id(self):
        return self._secret_id

    def _get_secrets_path(self):
        return self._secrets_path

    def _set_secrets_path(self, secrets_path):
        self._secrets_path = secrets_path

    secrets_path = property(
        _get_secrets_path,
        _set_secrets_path,
        doc='The path for the file containing the encrypted symmetric secret.')

    @property
    def passphrase(self):
        """
        Return the passphrase for locking and unlocking encryption secrets for
        local and remote storage.
        """
        return self._passphrase

    def _passphrase_as_string(self):
        return self._passphrase.encode('utf-8')

    #
    # remote storage secret
    #

    @property
    def remote_storage_secret(self):
        """
        Return the secret for remote storage.
        """
        key_start = 0
        key_end = self.REMOTE_STORAGE_SECRET_LENGTH
        return self.storage_secret[key_start:key_end]

    #
    # local storage key
    #

    def _get_local_storage_secret(self):
        """
        Return the local storage secret.

        :return: The local storage secret.
        :rtype: str
        """
        secret_len = self.REMOTE_STORAGE_SECRET_LENGTH
        lsecret_len = self.LOCAL_STORAGE_SECRET_LENGTH
        pwd_start = secret_len + self.SALT_LENGTH
        pwd_end = secret_len + lsecret_len
        return self.storage_secret[pwd_start:pwd_end]

    def _get_local_storage_salt(self):
        """
        Return the local storage salt.

        :return: The local storage salt.
        :rtype: str
        """
        salt_start = self.REMOTE_STORAGE_SECRET_LENGTH
        salt_end = salt_start + self.SALT_LENGTH
        return self.storage_secret[salt_start:salt_end]

    def get_local_storage_key(self):
        """
        Return the local storage key derived from the local storage secret.

        :return: The key for protecting the local database.
        :rtype: str
        """
        return scrypt.hash(
            password=self._get_local_storage_secret(),
            salt=self._get_local_storage_salt(),
            buflen=32,  # we need a key with 256 bits (32 bytes)
        )

    #
    # sync db key
    #

    def _get_sync_db_salt(self):
        """
        Return the salt for sync db.
        """
        salt_start = self.LOCAL_STORAGE_SECRET_LENGTH \
            + self.REMOTE_STORAGE_SECRET_LENGTH
        salt_end = salt_start + self.SALT_LENGTH
        return self.storage_secret[salt_start:salt_end]

    def get_sync_db_key(self):
        """
        Return the key for protecting the sync database.

        :return: The key for protecting the sync database.
        :rtype: str
        """
        return scrypt.hash(
            password=self._get_local_storage_secret(),
            salt=self._get_sync_db_salt(),
            buflen=32,  # we need a key with 256 bits (32 bytes)
        )

    def _get_user_data(self):
        return {'uuid': self._uuid, 'userid': self._userid}
