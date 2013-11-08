# -*- coding: utf-8 -*-
# __init__.py
# Copyright (C) 2013 LEAP
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
Soledad - Synchronization Of Locally Encrypted Data Among Devices.

Soledad is the part of LEAP that manages storage and synchronization of
application data. It is built on top of U1DB reference Python API and
implements (1) a SQLCipher backend for local storage in the client, (2) a
SyncTarget that encrypts data before syncing, and (3) a CouchDB backend for
remote storage in the server side.
"""
import binascii
import errno
import httplib
import logging
import os
import socket
import ssl
import urlparse

from hashlib import sha256

try:
    import cchardet as chardet
except ImportError:
    import chardet

from u1db.remote import http_client
from u1db.remote.ssl_match_hostname import match_hostname

import scrypt
import simplejson as json

from leap.common.config import get_path_prefix
from leap.soledad.common import SHARED_DB_NAME
from leap.soledad.common.errors import (
    InvalidTokenError,
    NotLockedError,
    AlreadyLockedError,
)

#
# Signaling function
#

SOLEDAD_CREATING_KEYS = 'Creating keys...'
SOLEDAD_DONE_CREATING_KEYS = 'Done creating keys.'
SOLEDAD_DOWNLOADING_KEYS = 'Downloading keys...'
SOLEDAD_DONE_DOWNLOADING_KEYS = 'Done downloading keys.'
SOLEDAD_UPLOADING_KEYS = 'Uploading keys...'
SOLEDAD_DONE_UPLOADING_KEYS = 'Done uploading keys.'
SOLEDAD_NEW_DATA_TO_SYNC = 'New data available.'
SOLEDAD_DONE_DATA_SYNC = 'Done data sync.'

# we want to use leap.common.events to emits signals, if it is available.
try:
    from leap.common import events
    from leap.common.events import signal
    SOLEDAD_CREATING_KEYS = events.events_pb2.SOLEDAD_CREATING_KEYS
    SOLEDAD_DONE_CREATING_KEYS = events.events_pb2.SOLEDAD_DONE_CREATING_KEYS
    SOLEDAD_DOWNLOADING_KEYS = events.events_pb2.SOLEDAD_DOWNLOADING_KEYS
    SOLEDAD_DONE_DOWNLOADING_KEYS = \
        events.events_pb2.SOLEDAD_DONE_DOWNLOADING_KEYS
    SOLEDAD_UPLOADING_KEYS = events.events_pb2.SOLEDAD_UPLOADING_KEYS
    SOLEDAD_DONE_UPLOADING_KEYS = \
        events.events_pb2.SOLEDAD_DONE_UPLOADING_KEYS
    SOLEDAD_NEW_DATA_TO_SYNC = events.events_pb2.SOLEDAD_NEW_DATA_TO_SYNC
    SOLEDAD_DONE_DATA_SYNC = events.events_pb2.SOLEDAD_DONE_DATA_SYNC

except ImportError:
    # we define a fake signaling function and fake signal constants that will
    # allow for logging signaling attempts in case leap.common.events is not
    # available.

    def signal(signal, content=""):
        logger.info("Would signal: %s - %s." % (str(signal), content))


from leap.soledad.common import soledad_assert, soledad_assert_type
from leap.soledad.common.document import SoledadDocument
from leap.soledad.client.crypto import SoledadCrypto
from leap.soledad.client.shared_db import SoledadSharedDatabase
from leap.soledad.client.sqlcipher import open as sqlcipher_open
from leap.soledad.client.sqlcipher import SQLCipherDatabase
from leap.soledad.client.target import SoledadSyncTarget


logger = logging.getLogger(name=__name__)


#
# Constants
#

SOLEDAD_CERT = None
"""
Path to the certificate file used to certify the SSL connection between
Soledad client and server.
"""


#
# Soledad: local encrypted storage and remote encrypted sync.
#

class NoStorageSecret(Exception):
    """
    Raised when trying to use a storage secret but none is available.
    """
    pass


class PassphraseTooShort(Exception):
    """
    Raised when trying to change the passphrase but the provided passphrase is
    too short.
    """


class BootstrapSequenceError(Exception):
    """
    Raised when an attempt to generate a secret and store it in a recovery
    documents on server failed.
    """


class Soledad(object):
    """
    Soledad provides encrypted data storage and sync.

    A Soledad instance is used to store and retrieve data in a local encrypted
    database and synchronize this database with Soledad server.

    This class is also responsible for bootstrapping users' account by
    creating cryptographic secrets and/or storing/fetching them on Soledad
    server.

    Soledad uses C{leap.common.events} to signal events. The possible events
    to be signaled are:

        SOLEDAD_CREATING_KEYS: emitted during bootstrap sequence when key
            generation starts.
        SOLEDAD_DONE_CREATING_KEYS: emitted during bootstrap sequence when key
            generation finishes.
        SOLEDAD_UPLOADING_KEYS: emitted during bootstrap sequence when soledad
            starts sending keys to server.
        SOLEDAD_DONE_UPLOADING_KEYS: emitted during bootstrap sequence when
            soledad finishes sending keys to server.
        SOLEDAD_DOWNLOADING_KEYS: emitted during bootstrap sequence when
            soledad starts to retrieve keys from server.
        SOLEDAD_DONE_DOWNLOADING_KEYS: emitted during bootstrap sequence when
            soledad finishes downloading keys from server.
        SOLEDAD_NEW_DATA_TO_SYNC: emitted upon call to C{need_sync()} when
          there's indeed new data to be synchronized between local database
          replica and server's replica.
        SOLEDAD_DONE_DATA_SYNC: emitted inside C{sync()} method when it has
            finished synchronizing with remote replica.
    """

    LOCAL_DATABASE_FILE_NAME = 'soledad.u1db'
    """
    The name of the local SQLCipher U1DB database file.
    """

    STORAGE_SECRETS_FILE_NAME = "soledad.json"
    """
    The name of the file where the storage secrets will be stored.
    """

    GENERATED_SECRET_LENGTH = 1024
    """
    The length of the generated secret used to derive keys for symmetric
    encryption for local and remote storage.
    """

    LOCAL_STORAGE_SECRET_LENGTH = 512
    """
    The length of the secret used to derive a passphrase for the SQLCipher
    database.
    """

    REMOTE_STORAGE_SECRET_LENGTH = \
        GENERATED_SECRET_LENGTH - LOCAL_STORAGE_SECRET_LENGTH
    """
    The length of the secret used to derive an encryption key and a MAC auth
    key for remote storage.
    """

    SALT_LENGTH = 64
    """
    The length of the salt used to derive the key for the storage secret
    encryption.
    """

    MINIMUM_PASSPHRASE_LENGTH = 6
    """
    The minimum length for a passphrase. The passphrase length is only checked
    when the user changes her passphrase, not when she instantiates Soledad.
    """

    IV_SEPARATOR = ":"
    """
    A separator used for storing the encryption initial value prepended to the
    ciphertext.
    """

    UUID_KEY = 'uuid'
    STORAGE_SECRETS_KEY = 'storage_secrets'
    SECRET_KEY = 'secret'
    CIPHER_KEY = 'cipher'
    LENGTH_KEY = 'length'
    KDF_KEY = 'kdf'
    KDF_SALT_KEY = 'kdf_salt'
    KDF_LENGTH_KEY = 'kdf_length'
    KDF_SCRYPT = 'scrypt'
    CIPHER_AES256 = 'aes256'
    """
    Keys used to access storage secrets in recovery documents.
    """

    DEFAULT_PREFIX = os.path.join(get_path_prefix(), 'leap', 'soledad')
    """
    Prefix for default values for path.
    """

    def __init__(self, uuid, passphrase, secrets_path, local_db_path,
                 server_url, cert_file, auth_token=None, secret_id=None):
        """
        Initialize configuration, cryptographic keys and dbs.

        :param uuid: User's uuid.
        :type uuid: str
        :param passphrase: The passphrase for locking and unlocking encryption
                           secrets for local and remote storage.
        :type passphrase: unicode
        :param secrets_path: Path for storing encrypted key used for
                             symmetric encryption.
        :type secrets_path: str
        :param local_db_path: Path for local encrypted storage db.
        :type local_db_path: str
        :param server_url: URL for Soledad server. This is used either to sync
            with the user's remote db and to interact with the shared recovery
            database.
        :type server_url: str
        :param cert_file: Path to the certificate of the ca used
                          to validate the SSL certificate used by the remote
                          soledad server.
        :type cert_file: str
        :param auth_token: Authorization token for accessing remote databases.
        :type auth_token: str

        :raise BootstrapSequenceError: Raised when the secret generation and
            storage on server sequence has failed for some reason.
        """
        # get config params
        self._uuid = uuid
        soledad_assert_type(passphrase, unicode)
        self._passphrase = passphrase
        # init crypto variables
        self._secrets = {}
        self._secret_id = secret_id
        # init config (possibly with default values)
        self._init_config(secrets_path, local_db_path, server_url)
        self._set_token(auth_token)
        self._shared_db_instance = None
        # configure SSL certificate
        global SOLEDAD_CERT
        SOLEDAD_CERT = cert_file
        # initiate bootstrap sequence
        self._bootstrap()  # might raise BootstrapSequenceError()

    def _init_config(self, secrets_path, local_db_path, server_url):
        """
        Initialize configuration using default values for missing params.
        """
        # initialize secrets_path
        self._secrets_path = secrets_path
        if self._secrets_path is None:
            self._secrets_path = os.path.join(
                self.DEFAULT_PREFIX, self.STORAGE_SECRETS_FILE_NAME)
        # initialize local_db_path
        self._local_db_path = local_db_path
        if self._local_db_path is None:
            self._local_db_path = os.path.join(
                self.DEFAULT_PREFIX, self.LOCAL_DATABASE_FILE_NAME)
        # initialize server_url
        self._server_url = server_url
        soledad_assert(
            self._server_url is not None,
            'Missing URL for Soledad server.')

    #
    # initialization/destruction methods
    #

    def _bootstrap(self):
        """
        Bootstrap local Soledad instance.

        Soledad Client bootstrap is the following sequence of stages:

        * stage 0 - local environment setup.
            - directory initialization.
            - crypto submodule initialization
        * stage 1 - local secret loading:
            - if secrets exist locally, load them.
        * stage 2 - remote secret loading:
            - else, if secrets exist in server, download them.
        * stage 3 - secret generation:
            - else, generate a new secret and store in server.
        * stage 4 - database initialization.

        This method decides which bootstrap stages have already been performed
        and performs the missing ones in order.

        :raise BootstrapSequenceError: Raised when the secret generation and
            storage on server sequence has failed for some reason.
        """
        # STAGE 0  - local environment setup
        self._init_dirs()
        self._crypto = SoledadCrypto(self)

        # STAGE 1 - verify if secrets exist locally
        if not self._has_secret():  # try to load from local storage.

            # STAGE 2 - there are no secrets in local storage, so try to fetch
            # encrypted secrets from server.
            logger.info(
                'Trying to fetch cryptographic secrets from shared recovery '
                'database...')

            # --- start of atomic operation in shared db ---

            # obtain lock on shared db
            token = timeout = None
            try:
                token, timeout = self._shared_db.lock()
            except AlreadyLockedError:
                raise BootstrapSequenceError('Database is already locked.')

            doc = self._get_secrets_from_shared_db()
            if doc:
                logger.info(
                    'Found cryptographic secrets in shared recovery '
                    'database.')
                self.import_recovery_document(doc.content)
            else:
                # STAGE 3 - there are no secrets in server also, so
                # generate a secret and store it in remote db.
                logger.info(
                    'No cryptographic secrets found, creating new '
                    ' secrets...')
                self._set_secret_id(self._gen_secret())
                try:
                    self._put_secrets_in_shared_db()
                except Exception:
                    # storing generated secret in shared db failed for
                    # some reason, so we erase the generated secret and
                    # raise.
                    try:
                        os.unlink(self._secrets_path)
                    except OSError as e:
                        if errno == 2:  # no such file or directory
                            pass
                    raise BootstrapSequenceError(
                        'Could not store generated secret in the shared '
                        'database, bailing out...')

            # release the lock on shared db
            try:
                self._shared_db.unlock(token)
            except NotLockedError:
                # for some reason the lock expired. Despite that, secret
                # loading or generation/storage must have been executed
                # successfully, so we pass.
                pass
            except InvalidTokenError:
                # here, our lock has not only expired but also some other
                # client application has obtained a new lock and is currently
                # doing its thing in the shared database. Using the same
                # reasoning as above, we assume everything went smooth and
                # pass.
                pass
            except Exception as e:
                logger.error("Unhandled exception when unlocking shared "
                             "database.")
                logger.exception(e)

            # --- end of atomic operation in shared db ---

        # STAGE 4 - local database initialization
        self._init_db()

    def _init_dirs(self):
        """
        Create work directories.

        :raise OSError: in case file exists and is not a dir.
        """
        paths = map(
            lambda x: os.path.dirname(x),
            [self._local_db_path, self._secrets_path])
        for path in paths:
            try:
                if not os.path.isdir(path):
                    logger.info('Creating directory: %s.' % path)
                os.makedirs(path)
            except OSError as exc:
                if exc.errno == errno.EEXIST and os.path.isdir(path):
                    pass
                else:
                    raise

    def _init_db(self):
        """
        Initialize the U1DB SQLCipher database for local storage.

        Currently, Soledad uses the default SQLCipher cipher, i.e.
        'aes-256-cbc'. We use scrypt to derive a 256-bit encryption key and
        uses the 'raw PRAGMA key' format to handle the key to SQLCipher.

        The first C{self.REMOTE_STORAGE_SECRET_LENGTH} bytes of the storage
        secret are used for remote storage encryption. We use the next
        C{self.LOCAL_STORAGE_SECRET} bytes to derive a key for local storage.
        From these bytes, the first C{self.SALT_LENGTH} are used as the salt
        and the rest as the password for the scrypt hashing.
        """
        # salt indexes
        salt_start = self.REMOTE_STORAGE_SECRET_LENGTH
        salt_end = salt_start + self.SALT_LENGTH
        # password indexes
        pwd_start = salt_end
        pwd_end = salt_start + self.LOCAL_STORAGE_SECRET_LENGTH
        # calculate the key for local encryption
        secret = self._get_storage_secret()
        key = scrypt.hash(
            secret[pwd_start:pwd_end],  # the password
            secret[salt_start:salt_end],  # the salt
            buflen=32,  # we need a key with 256 bits (32 bytes)
        )

        self._db = sqlcipher_open(
            self._local_db_path,
            binascii.b2a_hex(key),  # sqlcipher only accepts the hex version
            create=True,
            document_factory=SoledadDocument,
            crypto=self._crypto,
            raw_key=True)

    def close(self):
        """
        Close underlying U1DB database.
        """
        if hasattr(self, '_db') and isinstance(
                self._db,
                SQLCipherDatabase):
            self._db.close()

    def __del__(self):
        """
        Make sure local database is closed when object is destroyed.
        """
        # Watch out! We have no guarantees  that this is properly called.
        self.close()

    #
    # Management of secret for symmetric encryption.
    #

    def _get_storage_secret(self):
        """
        Return the storage secret.

        Storage secret is encrypted before being stored. This method decrypts
        and returns the stored secret.

        :return: The storage secret.
        :rtype: str
        """
        # calculate the encryption key
        key = scrypt.hash(
            self._passphrase_as_string(),
            # the salt is stored base64 encoded
            binascii.a2b_base64(
                self._secrets[self._secret_id][self.KDF_SALT_KEY]),
            buflen=32,  # we need a key with 256 bits (32 bytes).
        )
        # recover the initial value and ciphertext
        iv, ciphertext = self._secrets[self._secret_id][self.SECRET_KEY].split(
            self.IV_SEPARATOR, 1)
        ciphertext = binascii.a2b_base64(ciphertext)
        return self._crypto.decrypt_sym(ciphertext, key, iv=iv)

    def _set_secret_id(self, secret_id):
        """
        Define the id of the storage secret to be used.

        This method will also replace the secret in the crypto object.
        """
        self._secret_id = secret_id

    def _load_secrets(self):
        """
        Load storage secrets from local file.

        The content of the file has the following format:

            {
                "storage_secrets": {
                    "<secret_id>": {
                        'kdf': 'scrypt',
                        'kdf_salt': '<b64 repr of salt>'
                        'kdf_length': <key length>
                        "cipher": "aes256",
                        "length": <secret length>,
                        "secret": "<encrypted storage_secret 1>",
                    }
                }
            }
        """
        # does the file exist in disk?
        if not os.path.isfile(self._secrets_path):
            raise IOError('File does not exist: %s' % self._secrets_path)
        # read storage secrets from file
        content = None
        with open(self._secrets_path, 'r') as f:
            content = json.loads(f.read())
        self._secrets = content[self.STORAGE_SECRETS_KEY]
        # choose first secret if no secret_id was given
        if self._secret_id is None:
            self._set_secret_id(self._secrets.items()[0][0])

    def _has_secret(self):
        """
        Return whether there is a storage secret available for use or not.

        :return: Whether there's a storage secret for symmetric encryption.
        :rtype: bool
        """
        if self._secret_id is None or self._secret_id not in self._secrets:
            try:
                self._load_secrets()  # try to load from disk
            except IOError, e:
                logger.warning('IOError: %s' % str(e))
        try:
            self._get_storage_secret()
            return True
        except Exception:
            return False

    def _gen_secret(self):
        """
        Generate a secret for symmetric encryption and store in a local
        encrypted file.

        This method emits the following signals:

            * SOLEDAD_CREATING_KEYS
            * SOLEDAD_DONE_CREATING_KEYS

        A secret has the following structure:

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

        :return: The id of the generated secret.
        :rtype: str
        """
        signal(SOLEDAD_CREATING_KEYS, self._uuid)
        # generate random secret
        secret = os.urandom(self.GENERATED_SECRET_LENGTH)
        secret_id = sha256(secret).hexdigest()
        # generate random salt
        salt = os.urandom(self.SALT_LENGTH)
        # get a 256-bit key
        key = scrypt.hash(self._passphrase_as_string(), salt, buflen=32)
        iv, ciphertext = self._crypto.encrypt_sym(secret, key)
        self._secrets[secret_id] = {
            # leap.soledad.crypto submodule uses AES256 for symmetric
            # encryption.
            self.KDF_KEY: self.KDF_SCRYPT,
            self.KDF_SALT_KEY: binascii.b2a_base64(salt),
            self.KDF_LENGTH_KEY: len(key),
            self.CIPHER_KEY: self.CIPHER_AES256,
            self.LENGTH_KEY: len(secret),
            self.SECRET_KEY: '%s%s%s' % (
                str(iv), self.IV_SEPARATOR, binascii.b2a_base64(ciphertext)),
        }
        self._store_secrets()
        signal(SOLEDAD_DONE_CREATING_KEYS, self._uuid)
        return secret_id

    def _store_secrets(self):
        """
        Store a secret in C{Soledad.STORAGE_SECRETS_FILE_PATH}.

        The contents of the stored file have the following format:

            {
                'storage_secrets': {
                    '<secret_id>': {
                        'kdf': 'scrypt',
                        'kdf_salt': '<salt>'
                        'kdf_length': <len>
                        'cipher': 'aes256',
                        'length': 1024,
                        'secret': '<encrypted storage_secret 1>',
                    }
                }
            }
        """
        data = {
            self.STORAGE_SECRETS_KEY: self._secrets,
        }
        with open(self._secrets_path, 'w') as f:
            f.write(json.dumps(data))

    def change_passphrase(self, new_passphrase):
        """
        Change the passphrase that encrypts the storage secret.

        :param new_passphrase: The new passphrase.
        :type new_passphrase: unicode

        :raise NoStorageSecret: Raised if there's no storage secret available.
        """
        # maybe we want to add more checks to guarantee passphrase is
        # reasonable?
        soledad_assert_type(new_passphrase, unicode)
        if len(new_passphrase) < self.MINIMUM_PASSPHRASE_LENGTH:
            raise PassphraseTooShort(
                'Passphrase must be at least %d characters long!' %
                self.MINIMUM_PASSPHRASE_LENGTH)
        # ensure there's a secret for which the passphrase will be changed.
        if not self._has_secret():
            raise NoStorageSecret()
        secret = self._get_storage_secret()
        # generate random salt
        new_salt = os.urandom(self.SALT_LENGTH)
        # get a 256-bit key
        key = scrypt.hash(new_passphrase.encode('utf-8'), new_salt, buflen=32)
        iv, ciphertext = self._crypto.encrypt_sym(secret, key)
        self._secrets[self._secret_id] = {
            # leap.soledad.crypto submodule uses AES256 for symmetric
            # encryption.
            self.KDF_KEY: self.KDF_SCRYPT,  # TODO: remove hard coded kdf
            self.KDF_SALT_KEY: binascii.b2a_base64(new_salt),
            self.KDF_LENGTH_KEY: len(key),
            self.CIPHER_KEY: self.CIPHER_AES256,
            self.LENGTH_KEY: len(secret),
            self.SECRET_KEY: '%s%s%s' % (
                str(iv), self.IV_SEPARATOR, binascii.b2a_base64(ciphertext)),
        }

        self._store_secrets()
        self._passphrase = new_passphrase

    #
    # General crypto utility methods.
    #

    @property
    def _shared_db(self):
        """
        Return an instance of the shared recovery database object.

        :return: The shared database.
        :rtype: SoledadSharedDatabase
        """
        if self._shared_db_instance is None:
            self._shared_db_instance = SoledadSharedDatabase.open_database(
                urlparse.urljoin(self.server_url, SHARED_DB_NAME),
                self._uuid,
                False,  # db should exist at this point.
                creds=self._creds)
        return self._shared_db_instance

    def _shared_db_doc_id(self):
        """
        Calculate the doc_id of the document in the shared db that stores key
        material.

        :return: the hash
        :rtype: str
        """
        return sha256('%s%s' %
                     (self._passphrase_as_string(), self.uuid)).hexdigest()

    def _get_secrets_from_shared_db(self):
        """
        Retrieve the document with encrypted key material from the shared
        database.

        :return: a document with encrypted key material in its contents
        :rtype: SoledadDocument
        """
        signal(SOLEDAD_DOWNLOADING_KEYS, self._uuid)
        db = self._shared_db
        if not db:
            logger.warning('No shared db found')
            return
        doc = db.get_doc(self._shared_db_doc_id())
        signal(SOLEDAD_DONE_DOWNLOADING_KEYS, self._uuid)
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
            doc = SoledadDocument(
                doc_id=self._shared_db_doc_id())
        # fill doc with encrypted secrets
        doc.content = self.export_recovery_document(include_uuid=False)
        # upload secrets to server
        signal(SOLEDAD_UPLOADING_KEYS, self._uuid)
        db = self._shared_db
        if not db:
            logger.warning('No shared db found')
            return
        db.put_doc(doc)
        signal(SOLEDAD_DONE_UPLOADING_KEYS, self._uuid)

    #
    # Document storage, retrieval and sync.
    #

    def put_doc(self, doc):
        """
        Update a document in the local encrypted database.

        :param doc: the document to update
        :type doc: SoledadDocument

        :return: the new revision identifier for the document
        :rtype: str
        """
        return self._db.put_doc(doc)

    def delete_doc(self, doc):
        """
        Delete a document from the local encrypted database.

        :param doc: the document to delete
        :type doc: SoledadDocument

        :return: the new revision identifier for the document
        :rtype: str
        """
        return self._db.delete_doc(doc)

    def get_doc(self, doc_id, include_deleted=False):
        """
        Retrieve a document from the local encrypted database.

        :param doc_id: the unique document identifier
        :type doc_id: str
        :param include_deleted: if True, deleted documents will be
                                returned with empty content; otherwise asking
                                for a deleted document will return None
        :type include_deleted: bool

        :return: the document object or None
        :rtype: SoledadDocument
        """
        return self._db.get_doc(doc_id, include_deleted=include_deleted)

    def get_docs(self, doc_ids, check_for_conflicts=True,
                 include_deleted=False):
        """
        Get the content for many documents.

        :param doc_ids: a list of document identifiers
        :type doc_ids: list
        :param check_for_conflicts: if set False, then the conflict check will
            be skipped, and 'None' will be returned instead of True/False
        :type check_for_conflicts: bool

        :return: iterable giving the Document object for each document id
            in matching doc_ids order.
        :rtype: generator
        """
        return self._db.get_docs(doc_ids,
                                 check_for_conflicts=check_for_conflicts,
                                 include_deleted=include_deleted)

    def get_all_docs(self, include_deleted=False):
        """Get the JSON content for all documents in the database.

        :param include_deleted: If set to True, deleted documents will be
                                returned with empty content. Otherwise deleted
                                documents will not be included in the results.
        :return: (generation, [Document])
                 The current generation of the database, followed by a list of
                 all the documents in the database.
        """
        return self._db.get_all_docs(include_deleted)

    def _convert_to_unicode(self, content):
        """
        Converts content to utf8 (or all the strings in content)

        NOTE: Even though this method supports any type, it will
        currently ignore contents of lists, tuple or any other
        iterable than dict. We don't need support for these at the
        moment

        :param content: content to convert
        :type content: object

        :rtype: object
        """
        if isinstance(content, unicode):
            return content
        elif isinstance(content, str):
            try:
                result = chardet.detect(content)
                default = "utf-8"
                encoding = result["encoding"] or default
                content = content.decode(encoding)
            except UnicodeError:
                pass
            return content
        else:
            if isinstance(content, dict):
                for key in content.keys():
                    content[key] = self._convert_to_unicode(content[key])
        return content

    def create_doc(self, content, doc_id=None):
        """
        Create a new document in the local encrypted database.

        :param content: the contents of the new document
        :type content: dict
        :param doc_id: an optional identifier specifying the document id
        :type doc_id: str

        :return: the new document
        :rtype: SoledadDocument
        """
        return self._db.create_doc(
            self._convert_to_unicode(content), doc_id=doc_id)

    def create_doc_from_json(self, json, doc_id=None):
        """
        Create a new document.

        You can optionally specify the document identifier, but the document
        must not already exist. See 'put_doc' if you want to override an
        existing document.
        If the database specifies a maximum document size and the document
        exceeds it, create will fail and raise a DocumentTooBig exception.

        :param json: The JSON document string
        :type json: str
        :param doc_id: An optional identifier specifying the document id.
        :type doc_id:
        :return: The new cocument
        :rtype: SoledadDocument
        """
        return self._db.create_doc_from_json(json, doc_id=doc_id)

    def create_index(self, index_name, *index_expressions):
        """
        Create an named index, which can then be queried for future lookups.
        Creating an index which already exists is not an error, and is cheap.
        Creating an index which does not match the index_expressions of the
        existing index is an error.
        Creating an index will block until the expressions have been evaluated
        and the index generated.

        :param index_name: A unique name which can be used as a key prefix
        :type index_name: str
        :param index_expressions: index expressions defining the index
                                  information.
        :type index_expressions: dict

            Examples:

            "fieldname", or "fieldname.subfieldname" to index alphabetically
            sorted on the contents of a field.

            "number(fieldname, width)", "lower(fieldname)"
        """
        if self._db:
            return self._db.create_index(index_name, *index_expressions)

    def delete_index(self, index_name):
        """
        Remove a named index.

        :param index_name: The name of the index we are removing
        :type index_name: str
        """
        if self._db:
            return self._db.delete_index(index_name)

    def list_indexes(self):
        """
        List the definitions of all known indexes.

        :return: A list of [('index-name', ['field', 'field2'])] definitions.
        :rtype: list
        """
        if self._db:
            return self._db.list_indexes()

    def get_from_index(self, index_name, *key_values):
        """
        Return documents that match the keys supplied.

        You must supply exactly the same number of values as have been defined
        in the index. It is possible to do a prefix match by using '*' to
        indicate a wildcard match. You can only supply '*' to trailing entries,
        (eg 'val', '*', '*' is allowed, but '*', 'val', 'val' is not.)
        It is also possible to append a '*' to the last supplied value (eg
        'val*', '*', '*' or 'val', 'val*', '*', but not 'val*', 'val', '*')

        :param index_name: The index to query
        :type index_name: str
        :param key_values: values to match. eg, if you have
                           an index with 3 fields then you would have:
                           get_from_index(index_name, val1, val2, val3)
        :type key_values: tuple
        :return: List of [Document]
        :rtype: list
        """
        if self._db:
            return self._db.get_from_index(index_name, *key_values)

    def get_range_from_index(self, index_name, start_value, end_value):
        """
        Return documents that fall within the specified range.

        Both ends of the range are inclusive. For both start_value and
        end_value, one must supply exactly the same number of values as have
        been defined in the index, or pass None. In case of a single column
        index, a string is accepted as an alternative for a tuple with a single
        value. It is possible to do a prefix match by using '*' to indicate
        a wildcard match. You can only supply '*' to trailing entries, (eg
        'val', '*', '*' is allowed, but '*', 'val', 'val' is not.) It is also
        possible to append a '*' to the last supplied value (eg 'val*', '*',
        '*' or 'val', 'val*', '*', but not 'val*', 'val', '*')

        :param index_name: The index to query
        :type index_name: str
        :param start_values: tuples of values that define the lower bound of
            the range. eg, if you have an index with 3 fields then you would
            have: (val1, val2, val3)
        :type start_values: tuple
        :param end_values: tuples of values that define the upper bound of the
            range. eg, if you have an index with 3 fields then you would have:
            (val1, val2, val3)
        :type end_values: tuple
        :return: List of [Document]
        :rtype: list
        """
        if self._db:
            return self._db.get_range_from_index(
                index_name, start_value, end_value)

    def get_index_keys(self, index_name):
        """
        Return all keys under which documents are indexed in this index.

        :param index_name: The index to query
        :type index_name: str
        :return: [] A list of tuples of indexed keys.
        :rtype: list
        """
        if self._db:
            return self._db.get_index_keys(index_name)

    def get_doc_conflicts(self, doc_id):
        """
        Get the list of conflicts for the given document.

        :param doc_id: the document id
        :type doc_id: str

        :return: a list of the document entries that are conflicted
        :rtype: list
        """
        if self._db:
            return self._db.get_doc_conflicts(doc_id)

    def resolve_doc(self, doc, conflicted_doc_revs):
        """
        Mark a document as no longer conflicted.

        :param doc: a document with the new content to be inserted.
        :type doc: SoledadDocument
        :param conflicted_doc_revs: a list of revisions that the new content
                                    supersedes.
        :type conflicted_doc_revs: list
        """
        if self._db:
            return self._db.resolve_doc(doc, conflicted_doc_revs)

    def sync(self):
        """
        Synchronize the local encrypted replica with a remote replica.

        :param url: the url of the target replica to sync with
        :type url: str

        :return: the local generation before the synchronisation was
            performed.
        :rtype: str
        """
        if self._db:
            local_gen = self._db.sync(
                urlparse.urljoin(self.server_url, 'user-%s' % self._uuid),
                creds=self._creds, autocreate=True)
            signal(SOLEDAD_DONE_DATA_SYNC, self._uuid)
            return local_gen

    def need_sync(self, url):
        """
        Return if local db replica differs from remote url's replica.

        :param url: The remote replica to compare with local replica.
        :type url: str

        :return: Whether remote replica and local replica differ.
        :rtype: bool
        """
        target = SoledadSyncTarget(url, creds=self._creds, crypto=self._crypto)
        info = target.get_sync_info(self._db._get_replica_uid())
        # compare source generation with target's last known source generation
        if self._db._get_generation() != info[4]:
            signal(SOLEDAD_NEW_DATA_TO_SYNC, self._uuid)
            return True
        return False

    def _set_token(self, token):
        """
        Set the authentication token for remote database access.

        Build the credentials dictionary with the following format:

            self._{
                'token': {
                    'uuid': '<uuid>'
                    'token': '<token>'
            }

        :param token: The authentication token.
        :type token: str
        """
        self._creds = {
            'token': {
                'uuid': self._uuid,
                'token': token,
            }
        }

    def _get_token(self):
        """
        Return current token from credentials dictionary.
        """
        return self._creds['token']['token']

    token = property(_get_token, _set_token, doc='The authentication Token.')

    #
    # Recovery document export and import methods
    #

    def export_recovery_document(self, include_uuid=True):
        """
        Export the storage secrets and (optionally) the uuid.

        A recovery document has the following structure:

            {
                self.STORAGE_SECRET_KEY: <secrets dict>,
                self.UUID_KEY: '<uuid>',  # (optional)
            }

        :param include_uuid: Should the uuid be included?
        :type include_uuid: bool

        :return: The recovery document.
        :rtype: dict
        """
        data = {self.STORAGE_SECRETS_KEY: self._secrets}
        if include_uuid:
            data[self.UUID_KEY] = self._uuid
        return data

    def import_recovery_document(self, data):
        """
        Import storage secrets for symmetric encryption and uuid (if present)
        from a recovery document.

        A recovery document has the following structure:

            {
                self.STORAGE_SECRET_KEY: <secrets dict>,
                self.UUID_KEY: '<uuid>',  # (optional)
            }

        :param data: The recovery document.
        :type data: dict
        """
        # include new secrets in our secret pool.
        for secret_id, secret_data in data[self.STORAGE_SECRETS_KEY].items():
            if secret_id not in self._secrets:
                self._secrets[secret_id] = secret_data
        self._store_secrets()  # save new secrets in local file
        # set uuid if present
        if self.UUID_KEY in data:
            self._uuid = data[self.UUID_KEY]
        # choose first secret to use is none is assigned
        if self._secret_id is None:
            self._set_secret_id(data[self.STORAGE_SECRETS_KEY].items()[0][0])

    #
    # Setters/getters
    #

    def _get_uuid(self):
        return self._uuid

    uuid = property(_get_uuid, doc='The user uuid.')

    def _get_secret_id(self):
        return self._secret_id

    secret_id = property(
        _get_secret_id,
        doc='The active secret id.')

    def _get_secrets_path(self):
        return self._secrets_path

    secrets_path = property(
        _get_secrets_path,
        doc='The path for the file containing the encrypted symmetric secret.')

    def _get_local_db_path(self):
        return self._local_db_path

    local_db_path = property(
        _get_local_db_path,
        doc='The path for the local database replica.')

    def _get_server_url(self):
        return self._server_url

    server_url = property(
        _get_server_url,
        doc='The URL of the Soledad server.')

    storage_secret = property(
        _get_storage_secret,
        doc='The secret used for symmetric encryption.')

    def _get_passphrase(self):
        return self._passphrase

    passphrase = property(
        _get_passphrase,
        doc='The passphrase for locking and unlocking encryption secrets for '
            'local and remote storage.')

    def _passphrase_as_string(self):
        return self._passphrase.encode('utf-8')


#-----------------------------------------------------------------------------
# Monkey patching u1db to be able to provide a custom SSL cert
#-----------------------------------------------------------------------------

# We need a more reasonable timeout (in seconds)
SOLEDAD_TIMEOUT = 10


class VerifiedHTTPSConnection(httplib.HTTPSConnection):
    """
    HTTPSConnection verifying server side certificates.
    """
    # derived from httplib.py

    def connect(self):
        "Connect to a host on a given (SSL) port."
        sock = socket.create_connection((self.host, self.port),
                                        SOLEDAD_TIMEOUT, self.source_address)
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()

        self.sock = ssl.wrap_socket(sock,
                                    ca_certs=SOLEDAD_CERT,
                                    cert_reqs=ssl.CERT_REQUIRED)
        match_hostname(self.sock.getpeercert(), self.host)


old__VerifiedHTTPSConnection = http_client._VerifiedHTTPSConnection
http_client._VerifiedHTTPSConnection = VerifiedHTTPSConnection


__all__ = ['soledad_assert', 'Soledad']

from ._version import get_versions
__version__ = get_versions()['version']
del get_versions
