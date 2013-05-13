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

import os
import string
import binascii
import logging
import urlparse
import simplejson as json
import scrypt
import httplib
import socket
import ssl


from xdg import BaseDirectory
from hashlib import sha256
from u1db.remote import http_client
from u1db.remote.ssl_match_hostname import (  # noqa
    CertificateError,
    match_hostname,
)


from leap.common import events
from leap.common.check import leap_assert
from leap.common.files import mkdir_p
from leap.common.keymanager.errors import DecryptionFailed
from leap.soledad.backends import sqlcipher
from leap.soledad.backends.leap_backend import (
    LeapDocument,
    DocumentNotEncrypted,
    LeapSyncTarget,
)

from leap.soledad import shared_db
from leap.soledad.shared_db import SoledadSharedDatabase
from leap.soledad.crypto import SoledadCrypto


logger = logging.getLogger(name=__name__)


SOLEDAD_CERT = None
"""
Path to the certificate file used to certify the SSL connection between
Soledad client and server.
"""


#
# Exceptions
#

class KeyDoesNotExist(Exception):
    """
    Soledad attempted to find a key that does not exist locally.
    """


class KeyAlreadyExists(Exception):
    """
    Soledad attempted to create a key that already exists locally.
    """


class NotADirectory(Exception):
    """
    Expected a path for a directory but got some other thing.
    """


#
# Helper functions
#

def base64_encode(data):
    """
    Return the base64 encoded version of C{data}.

    @return: The base64 encoded version of C{data}.
    @rtype: str
    """
    # binascii.b2a_base64 returns a new line character in the end of the
    # string, so we strip that here.
    return binascii.b2a_base64(data)[:-1]


#
# Soledad: local encrypted storage and remote encrypted sync.
#

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

    STORAGE_SECRETS_FILE_NAME = "soledad.json"
    """
    The name of the file where the storage secrets will be stored.
    """

    STORAGE_SECRET_LENGTH = 512
    """
    The length of the secret used for symmetric encryption.
    """

    SALT_LENGTH = 64
    """
    The length of the salt used to derive the key for the storage secret
    encryption.
    """

    UUID_KEY = 'uuid'
    STORAGE_SECRETS_KEY = 'storage_secrets'
    SECRET_KEY = 'secret'
    CIPHER_KEY = 'cipher'
    LENGTH_KEY = 'length'
    KDF_KEY = 'kdf'
    KDF_SALT_KEY = 'kdf_salt'
    KDF_LENGTH_KEY = 'kdf_length'
    """
    Keys used to access storage secrets in recovery documents.
    """

    DEFAULT_PREFIX = os.path.join(
        BaseDirectory.xdg_config_home,
        'leap', 'soledad')
    """
    Prefix for default values for path.
    """

    def __init__(self, uuid, passphrase, secrets_path, local_db_path,
                 server_url, cert_file, auth_token=None):
        """
        Initialize configuration, cryptographic keys and dbs.

        @param uuid: User's uuid.
        @type uuid: str
        @param passphrase: The passphrase for locking and unlocking encryption
            secrets for disk storage.
        @type passphrase: str
        @param secrets_path: Path for storing encrypted key used for
            symmetric encryption.
        @type secrets_path: str
        @param local_db_path: Path for local encrypted storage db.
        @type local_db_path: str
        @param server_url: URL for Soledad server. This is used either to sync
            with the user's remote db and to interact with the shared recovery
            database.
        @type server_url: str
        @param cert_file: Path to the SSL certificate to use in the
            connection to the server_url.
        @type cert_file: str
        @param auth_token: Authorization token for accessing remote databases.
        @type auth_token: str
        """
        # get config params
        self._uuid = uuid
        self._passphrase = passphrase
        # init crypto variables
        self._secrets = {}
        self._secret_id = None
        # init config (possibly with default values)
        self._init_config(secrets_path, local_db_path, server_url)
        self._set_token(auth_token)
        # configure SSL certificate
        SOLEDAD_CERT = cert_file
        # initiate bootstrap sequence
        self._bootstrap()

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
                self.DEFAULT_PREFIX, 'soledad.u1db')
        # initialize server_url
        self._server_url = server_url
        leap_assert(
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
        * stage 1 - secret generation/loading:
            - if secrets exist locally, load them.
            - else, if secrets exist in server, download them.
            - else, generate a new secret.
        * stage 2 - store secrets in server.
        * stage 3 - database initialization.

        This method decides which bootstrap stages have already been performed
        and performs the missing ones in order.
        """
        # TODO: make sure key storage always happens (even if this method is
        #       interrupted).
        # TODO: write tests for bootstrap stages.
        # TODO: log each bootstrap step.
        # stage 0  - socal environment setup
        self._init_dirs()
        self._crypto = SoledadCrypto(self)
        # stage 1 - secret generation/loading
        if not self._has_secret():  # try to load from local storage.
            logger.info(
                'Trying to fetch cryptographic secrets from shared recovery '
                'database...')
            # there are no secrets in local storage, so try to fetch encrypted
            # secrets from server.
            doc = self._get_secrets_from_shared_db()
            if doc:
                # found secrets in server, so import them.
                logger.info(
                    'Found cryptographic secrets in shared recovery '
                    'database.')
                self.import_recovery_document(
                        doc.content[self.SECRET_KEY],
                        passphrase=self._passphrase)
            else:
                # there are no secrets in server also, so generate a secret.
                logger.info(
                    'No cryptographic secrets found, creating new secrets...')
                self._set_secret_id(self._gen_secret())
        # Stage 2 - storage of encrypted secrets in the server.
        self._put_secrets_in_shared_db()
        # Stage 3 - Local database initialization
        self._init_db()

    def _init_dirs(self):
        """
        Create work directories.

        @raise OSError: in case file exists and is not a dir.
        """
        paths = map(
            lambda x: os.path.dirname(x),
            [self.local_db_path, self._secrets_path])
        for path in paths:
            logger.info('Creating directory: %s.' % path)
            mkdir_p(path)

    def _init_db(self):
        """
        Initialize the database for local storage.
        """
        # instantiate u1db
        # TODO: verify if secret for sqlcipher should be the same as the
        # one for symmetric encryption.
        self._db = sqlcipher.open(
            self.local_db_path,
            self._get_storage_secret(),
            create=True,
            document_factory=LeapDocument,
            crypto=self._crypto)

    def close(self):
        """
        Close underlying U1DB database.
        """
        if hasattr(self, '_db') and isinstance(
                self._db,
                sqlcipher.SQLCipherDatabase):
            self._db.close()

    def __del__(self):
        """
        Make sure local database is closed when object is destroyed.
        """
        self.close()

    #
    # Management of secret for symmetric encryption.
    #

    def _get_storage_secret(self):
        """
        Return the base64 encoding of the storage secret.

        Storage secret is first base64 encoded and then encrypted before being
        stored. This message only decrypts the stored secret and returns the
        base64 encoded version.

        @return: The base64 encoding of the storage secret.
        @rtype: str
        """
        key = base64_encode(
            scrypt.hash(
                self._passphrase,
                # the salt is also stored as base64 encoded string, so make
                # direct use of this encoded version to derive the encryption
                # key.
                self._secrets[self._secret_id][self.KDF_SALT_KEY]))
        return self._crypto.decrypt_sym(
            self._secrets[self._secret_id][self.SECRET_KEY],
            passphrase=key)

    def _set_secret_id(self, secret_id):
        """
        Define the id of the storage secret to be used.

        This method will also replace the secret in the crypto object.
        """
        self._secret_id = secret_id
        self._crypto.secret = self._get_storage_secret()

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

        @raise leap.common.keymanager.errors.DecryptionFailed: Raised if could
            not decrypt the secret with the given passphrase.
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
        if self._secret_id == None:
            self._set_secret_id(self._secrets.items()[0][0])
        # check secret is isncrypted
        if not self._crypto.is_encrypted_sym(
                self._secrets[self._secret_id][self.SECRET_KEY]):
            raise DocumentNotEncrypted(
                "File %s is not encrypted!" % self._secrets_path)

    def _has_secret(self):
        """
        Return whether there is a storage secret available for use or not.

        @return: Whether there's a storage secret for symmetric encryption.
        @rtype: bool
        """
        # if the secret is already loaded, return true
        if self._secret_id is not None and self._secret_id in self._secrets:
            return True
        # try to load from disk
        try:
            self._load_secrets()
            return True
        except DecryptionFailed:
            logger.error('Could not decrypt storage secret.')
        except IOError, e: 
            logger.error('IOError: %s' % str(e))
        return False

    def _gen_secret(self):
        """
        Generate a secret for symmetric encryption and store in a local
        encrypted file.

        This method emits the following signals:

            * leap.common.events.events_pb2.SOLEDAD_CREATING_KEYS
            * leap.common.events.events_pb2.SOLEDAD_DONE_CREATING_KEYS

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

        @return: The id of the generated secret.
        @rtype: str
        """
        events.signal(events.events_pb2.SOLEDAD_CREATING_KEYS, self._uuid)
        # generate random secret
        secret = os.urandom(self.STORAGE_SECRET_LENGTH)
        secret_id = sha256(secret).hexdigest()
        # generate random salt
        base64_salt = base64_encode(os.urandom(self.SALT_LENGTH))
        key = scrypt.hash(self._passphrase, base64_salt)
        self._secrets[secret_id] = {
            # leap.common.keymanager.openpgp uses AES256 for symmetric
            # encryption.
            self.KDF_KEY: 'scrypt',  # TODO: remove hard coded kdf
            self.KDF_SALT_KEY: base64_salt,
            self.KDF_LENGTH_KEY: len(key),
            self.CIPHER_KEY: 'aes256',  # TODO: remove hard coded cipher
            self.LENGTH_KEY: len(secret),
            self.SECRET_KEY: self._crypto.encrypt_sym(
                base64_encode(secret),
                base64_encode(key)),
        }
        self._store_secrets()
        events.signal(
            events.events_pb2.SOLEDAD_DONE_CREATING_KEYS, self._uuid)
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
                        'length': 512,
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

    #
    # General crypto utility methods.
    #

    def _uuid_hash(self):
        """
        Calculate a hash for storing/retrieving key material on shared
        database, based on user's uuid.

        @return: the hash
        @rtype: str
        """
        return sha256('uuid-%s' % self._uuid).hexdigest()

    def _shared_db(self):
        """
        Return an instance of the shared recovery database object.
        """
        return SoledadSharedDatabase.open_database(
            urlparse.urljoin(self.server_url, 'shared'),
            False,  # TODO: eliminate need to create db here.
            creds=self._creds)

    def _get_secrets_from_shared_db(self):
        """
        Retrieve the document with encrypted key material from the shared
        database.

        @return: a document with encrypted key material in its contents
        @rtype: LeapDocument
        """
        events.signal(
            events.events_pb2.SOLEDAD_DOWNLOADING_KEYS, self._uuid)
        doc = self._shared_db().get_doc(self._uuid_hash())
        events.signal(
            events.events_pb2.SOLEDAD_DONE_DOWNLOADING_KEYS, self._uuid)
        return doc

    def _put_secrets_in_shared_db(self):
        """
        Assert local keys are the same as shared db's ones.

        Try to fetch keys from shared recovery database. If they already exist
        in the remote db, assert that that data is the same as local data.
        Otherwise, upload keys to shared recovery database.

        """
        leap_assert(
            self._has_secret(),
            'Tried to send keys to server but they don\'t exist in local '
            'storage.')
        # try to get secrets doc from server, otherwise create it
        doc = self._get_secrets_from_shared_db()
        if doc is None:
            doc = LeapDocument(doc_id=self._uuid_hash())
        # fill doc with encrypted secrets
        doc.content = {
            self.SECRET_KEY: self.export_recovery_document(
                self._passphrase)
        }
        # upload secrets to server
        events.signal(
            events.events_pb2.SOLEDAD_UPLOADING_KEYS, self._uuid)
        self._shared_db().put_doc(doc)
        events.signal(
            events.events_pb2.SOLEDAD_DONE_UPLOADING_KEYS, self._uuid)

    #
    # Document storage, retrieval and sync.
    #

    # TODO: refactor the following methods to somewhere out of here
    # (SoledadLocalDatabase, maybe?)

    def put_doc(self, doc):
        """
        Update a document in the local encrypted database.

        @param doc: the document to update
        @type doc: LeapDocument

        @return: the new revision identifier for the document
        @rtype: str
        """
        return self._db.put_doc(doc)

    def delete_doc(self, doc):
        """
        Delete a document from the local encrypted database.

        @param doc: the document to delete
        @type doc: LeapDocument

        @return: the new revision identifier for the document
        @rtype: str
        """
        return self._db.delete_doc(doc)

    def get_doc(self, doc_id, include_deleted=False):
        """
        Retrieve a document from the local encrypted database.

        @param doc_id: the unique document identifier
        @type doc_id: str
        @param include_deleted: if True, deleted documents will be
            returned with empty content; otherwise asking for a deleted
            document will return None
        @type include_deleted: bool

        @return: the document object or None
        @rtype: LeapDocument
        """
        return self._db.get_doc(doc_id, include_deleted=include_deleted)

    def get_docs(self, doc_ids, check_for_conflicts=True,
                 include_deleted=False):
        """
        Get the content for many documents.

        @param doc_ids: a list of document identifiers
        @type doc_ids: list
        @param check_for_conflicts: if set False, then the conflict check will
            be skipped, and 'None' will be returned instead of True/False
        @type check_for_conflicts: bool

        @return: iterable giving the Document object for each document id
            in matching doc_ids order.
        @rtype: generator
        """
        return self._db.get_docs(doc_ids,
                                 check_for_conflicts=check_for_conflicts,
                                 include_deleted=include_deleted)

    def get_all_docs(self, include_deleted=False):
        """Get the JSON content for all documents in the database.

        @param include_deleted: If set to True, deleted documents will be
            returned with empty content. Otherwise deleted documents will not
            be included in the results.
        @return: (generation, [Document])
            The current generation of the database, followed by a list of all
            the documents in the database.
        """
        return self._db.get_all_docs(include_deleted)

    def create_doc(self, content, doc_id=None):
        """
        Create a new document in the local encrypted database.

        @param content: the contents of the new document
        @type content: dict
        @param doc_id: an optional identifier specifying the document id
        @type doc_id: str

        @return: the new document
        @rtype: LeapDocument
        """
        return self._db.create_doc(content, doc_id=doc_id)

    def create_doc_from_json(self, json, doc_id=None):
        """
        Create a new document.

        You can optionally specify the document identifier, but the document
        must not already exist. See 'put_doc' if you want to override an
        existing document.
        If the database specifies a maximum document size and the document
        exceeds it, create will fail and raise a DocumentTooBig exception.

        @param json: The JSON document string
        @type json: str
        @param doc_id: An optional identifier specifying the document id.
        @type doc_id:
        @return: The new cocument
        @rtype: LeapDocument
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

        @param index_name: A unique name which can be used as a key prefix
        @type index_name: str
        @param index_expressions: index expressions defining the index
            information.
        @type index_expressions: dict

            Examples:

            "fieldname", or "fieldname.subfieldname" to index alphabetically
            sorted on the contents of a field.

            "number(fieldname, width)", "lower(fieldname)"
        """
        return self._db.create_index(index_name, *index_expressions)

    def delete_index(self, index_name):
        """
        Remove a named index.

        @param index_name: The name of the index we are removing
        @type index_name: str
        """
        return self._db.delete_index(index_name)

    def list_indexes(self):
        """
        List the definitions of all known indexes.

        @return: A list of [('index-name', ['field', 'field2'])] definitions.
        @rtype: list
        """
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

        @param index_name: The index to query
        @type index_name: str
        @param key_values: values to match. eg, if you have
            an index with 3 fields then you would have:
            get_from_index(index_name, val1, val2, val3)
        @type key_values: tuple
        @return: List of [Document]
        @rtype: list
        """
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

        @param index_name: The index to query
        @type index_name: str
        @param start_values: tuples of values that define the lower bound of
            the range. eg, if you have an index with 3 fields then you would
            have: (val1, val2, val3)
        @type start_values: tuple
        @param end_values: tuples of values that define the upper bound of the
            range. eg, if you have an index with 3 fields then you would have:
            (val1, val2, val3)
        @type end_values: tuple
        @return: List of [Document]
        @rtype: list
        """
        return self._db.get_range_from_index(
            index_name, start_value, end_value)

    def get_index_keys(self, index_name):
        """
        Return all keys under which documents are indexed in this index.

        @param index_name: The index to query
        @type index_name: str
        @return: [] A list of tuples of indexed keys.
        @rtype: list
        """
        return self._db.get_index_keys(index_name)

    def get_doc_conflicts(self, doc_id):
        """
        Get the list of conflicts for the given document.

        @param doc_id: the document id
        @type doc_id: str

        @return: a list of the document entries that are conflicted
        @rtype: list
        """
        return self._db.get_doc_conflicts(doc_id)

    def resolve_doc(self, doc, conflicted_doc_revs):
        """
        Mark a document as no longer conflicted.

        @param doc: a document with the new content to be inserted.
        @type doc: LeapDocument
        @param conflicted_doc_revs: a list of revisions that the new content
            supersedes.
        @type conflicted_doc_revs: list
        """
        return self._db.resolve_doc(doc, conflicted_doc_revs)

    def sync(self):
        """
        Synchronize the local encrypted replica with a remote replica.

        @param url: the url of the target replica to sync with
        @type url: str

        @return: the local generation before the synchronisation was
            performed.
        @rtype: str
        """
        local_gen = self._db.sync(
            urlparse.urljoin(self.server_url, 'user-%s' % self._uuid),
            creds=self._creds, autocreate=True)
        events.signal(events.events_pb2.SOLEDAD_DONE_DATA_SYNC, self._uuid)
        return local_gen

    def need_sync(self, url):
        """
        Return if local db replica differs from remote url's replica.

        @param url: The remote replica to compare with local replica.
        @type url: str

        @return: Whether remote replica and local replica differ.
        @rtype: bool
        """
        target = LeapSyncTarget(url, creds=self._creds, crypto=self._crypto)
        info = target.get_sync_info(self._db._get_replica_uid())
        # compare source generation with target's last known source generation
        if self._db._get_generation() != info[4]:
            events.signal(
                events.events_pb2.SOLEDAD_NEW_DATA_TO_SYNC, self._uuid)
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

        @param token: The authentication token.
        @type token: str
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
    # Recovery document export and import methodsecret
    def export_recovery_document(self, passphrase=None):
        """
        Exports username, provider, private key and key for symmetric
        encryption, optionally encrypted with a password.

        The LEAP client gives the user the option to export a text file with a
        complete copy of their private keys and authorization information,
        either password protected or not. This "recovery document" can be
        printed or saved electronically as the user sees fit. If the user
        needs to recover their data, they can load this recover document into
        any LEAP client. The user can also type the recovery document in
        manually, although it will be long and very painful to copy manually.

        Contents of recovery document:

           - username
           - provider
           - private key.
           - key for symmetric encryption

        @param passphrase: an optional passphrase for encrypting the document
        @type passphrase: str

        @return: the recovery document json serialization
        @rtype: str
        """
        data = json.dumps({
            self.UUID_KEY: self._uuid,
            self.STORAGE_SECRETS_KEY: self._secrets,
        })
        if passphrase:
            data = self._crypto.encrypt_sym(data, passphrase)
        return data

    def import_recovery_document(self, data, passphrase=None):
        """
        Import username, provider, private key and key for symmetric
        encryption from a recovery document.

        @param data: the recovery document json serialization
        @type data: str
        @param passphrase: an optional passphrase for decrypting the document
        @type passphrase: str
        """
        if passphrase and not self._crypto.is_encrypted_sym(data):
            raise DocumentNotEncrypted("You provided a password but the "
                                       "recovery document is not encrypted.")
        if passphrase:
            data = self._crypto.decrypt_sym(data, passphrase=passphrase)
        data = json.loads(data)
        # include new secrets in our secret pool.
        for secret_id, secret_data in data[self.STORAGE_SECRETS_KEY].items():
            if secret_id not in self._secrets:
                self._secrets[secret_id] = secret_data
        self._store_secrets()
        # set uuid
        self._uuid = data[self.UUID_KEY]
        # choose first secret to use
        self._set_secret_id(self._secrets.items()[0][0])

    #
    # Setters/getters
    #

    def _get_uuid(self):
        return self._uuid

    uuid = property(_get_uuid, doc='The user uuid.')

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


#-----------------------------------------------------------------------------
# Monkey patching u1db to be able to provide a custom SSL cert
#-----------------------------------------------------------------------------

class VerifiedHTTPSConnection(httplib.HTTPSConnection):
    """HTTPSConnection verifying server side certificates."""
    # derived from httplib.py

    def connect(self):
        "Connect to a host on a given (SSL) port."
        sock = socket.create_connection((self.host, self.port),
                                        self.timeout, self.source_address)
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
        self.sock = ssl.wrap_socket(sock, self.key_file, self.cert_file,
                                    ssl_version=ssl.PROTOCOL_SSLv3,
                                    cert_reqs=ssl.CERT_REQUIRED,
                                    ca_certs=SOLEDAD_CERT)
        match_hostname(self.sock.getpeercert(), self.host)


old__VerifiedHTTPSConnection = http_client._VerifiedHTTPSConnection
http_client._VerifiedHTTPSConnection = VerifiedHTTPSConnection
