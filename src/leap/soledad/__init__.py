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
import hashlib
import configparser
import re
import binascii
import logging
try:
    import simplejson as json
except ImportError:
    import json  # noqa


from hashlib import sha256


from leap.common import events
from leap.soledad.config import SoledadConfig
from leap.soledad.backends import sqlcipher
from leap.soledad.backends.leap_backend import (
    LeapDocument,
    DocumentNotEncrypted,
    LeapSyncTarget,
)
from leap.soledad.shared_db import SoledadSharedDatabase
from leap.soledad.crypto import SoledadCrypto


logger = logging.getLogger(name=__name__)


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

    SECRET_LENGTH = 50
    """
    The length of the secret used for symmetric encryption.
    """

    def __init__(self, address, passphrase, config_path=None,
                 secret_path=None, local_db_path=None,
                 shared_db_url=None, auth_token=None, bootstrap=True):
        """
        Initialize configuration, cryptographic keys and dbs.

        @param address: User's address in the form C{user@provider}.
        @type address: str
        @param passphrase: The passphrase for locking and unlocking encryption
            secrets for disk storage.
        @type passphrase: str
        @param config_path: Path for configuration file.
        @type config_path: str
        @param secret_path: Path for storing encrypted key used for
            symmetric encryption.
        @type secret_path: str
        @param local_db_path: Path for local encrypted storage db.
        @type local_db_path: str
        @param shared_db_url: URL for shared Soledad DB for key storage and
            unauth retrieval.
        @type shared_db_url: str
        @param auth_token: Authorization token for accessing remote databases.
        @type auth_token: str
        @param bootstrap: True/False, should bootstrap this instance? Mostly
            for testing purposes but can be useful for initialization control.
        @type bootstrap: bool
        """
        # TODO: allow for fingerprint enforcing.
        self._address = address
        self._passphrase = passphrase
        self._auth_token = auth_token
        self._init_config(
            config_path=config_path,
            secret_path=secret_path,
            local_db_path=local_db_path,
            shared_db_url=shared_db_url,
        )
        if bootstrap:
            self._bootstrap()

    def _bootstrap(self):
        """
        Bootstrap local Soledad instance.

        Soledad Client bootstrap is the following sequence of stages:

        * Stage 0 - Local environment setup.
            - directory initialization.
            - gnupg wrapper initialization.
        * Stage 1 - Keys generation/loading:
            - if keys exists locally, load them.
            - else, if keys exists in server, download them.
            - else, generate keys.
        * Stage 2 - Keys synchronization:
            - if keys exist in server, confirm we have the same keys
              locally.
            - else, send keys to server.
        * Stage 3 - Database initialization.

        This method decides which bootstrap stages have already been performed
        and performs the missing ones in order.
        """
        # TODO: make sure key storage always happens (even if this method is
        #       interrupted).
        # TODO: write tests for bootstrap stages.
        # TODO: log each bootstrap step.
        # Stage 0  - Local environment setup
        self._init_dirs()
        self._crypto = SoledadCrypto(self)
        if self._config.get_shared_db_url() and self._auth_token:
            # TODO: eliminate need to create db here.
            self._shared_db = SoledadSharedDatabase.open_database(
                self._config.get_shared_db_url(),
                True,
                token=self._auth_token)
        else:
            self._shared_db = None
        # Stage 1 - Keys generation/loading
        if self._has_keys():
            self._load_keys()
        else:
            doc = self._fetch_keys_from_shared_db()
            if not doc:
                self._init_keys()
            else:
                self._set_symkey(
                    self._crypto.decrypt_sym(
                        doc.content['_symkey'],
                        passphrase=self._address_hash()))
        # Stage 2 - Keys synchronization
        self._assert_server_keys()
        # Stage 3 - Local database initialization
        self._init_db()

    def _init_config(self, config_path, secret_path, local_db_path,
                     shared_db_url):
        """
        Initialize configuration using SoledadConfig.

        Soledad configuration makes use of BaseLeapConfig to load values from
        a file or from default configuration. Parameters passed as arguments
        for this method will supersede file and default values.

        @param kwargs: a dictionary with configuration parameter values passed
            when instantiating this Soledad instance.
        @type kwargs: dict
        """
        self._config = SoledadConfig()
        if config_path is not None:
            self._config.load(path=config_path)
        else:
            self._config.load(data='')
        # overwrite config with passed parameters
        if secret_path is not None:
            self._config._config_checker.config['secret_path'] = secret_path
        if local_db_path is not None:
            self._config._config_checker.config['local_db_path'] = local_db_path
        if shared_db_url is not None:
            self._config._config_checker.config['shared_db_url'] = shared_db_url

    def _init_dirs(self):
        """
        Create work directories.
        """
        paths = map(
            lambda x: os.path.dirname(x),
            [self._config.get_local_db_path(), self._config.get_secret_path()])
        for path in paths:
            if not os.path.isfile(path):
                if not os.path.isdir(path):
                    logger.info('Creating directory: %s.' % path)
                    os.makedirs(path)
                else:
                    logger.warning('Using existent directory: %s.' % path)
            else:
                raise NotADirectory(path)

    def _init_keys(self):
        """
        Generate (if needed) and load secret for symmetric encryption.
        """
        events.signal(events.events_pb2.SOLEDAD_CREATING_KEYS, self._address)
        # load/generate secret
        if not self._has_symkey():
            self._gen_symkey()
        self._load_symkey()
        events.signal(
            events.events_pb2.SOLEDAD_DONE_CREATING_KEYS, self._address)

    def _init_db(self):
        """
        Initialize the database for local storage.
        """
        # instantiate u1db
        # TODO: verify if secret for sqlcipher should be the same as the
        # one for symmetric encryption.
        self._db = sqlcipher.open(
            self._config.get_local_db_path(),
            self._symkey,
            create=True,
            document_factory=LeapDocument,
            crypto=self._crypto)

    def close(self):
        """
        Close underlying U1DB database.
        """
        self._db.close()

    #-------------------------------------------------------------------------
    # Management of secret for symmetric encryption
    #-------------------------------------------------------------------------

    def _has_symkey(self):
        """
        Verify if a key for symmetric encryption exists in a local encrypted
        file.

        @return: whether this soledad instance has a key for symmetric
            encryption
        @rtype: bool
        """
        # does the file exist in disk?
        if not os.path.isfile(self._config.get_secret_path()):
            return False
        # is it symmetrically encrypted?
        with open(self._config.get_secret_path(), 'r') as f:
            content = f.read()
        if not self._crypto.is_encrypted_sym(content):
            raise DocumentNotEncrypted(
                "File %s is not encrypted!" % self._config.get_secret_path())
        # can we decrypt it?
        plaintext = self._crypto.decrypt_sym(
            content, passphrase=self._passphrase)
        return plaintext != ''

    def _load_symkey(self):
        """
        Load secret for symmetric encryption from local encrypted file.
        """
        if not self._has_symkey():
            raise KeyDoesNotExist("Tried to load key for symmetric "
                                  "encryption but it does not exist on disk.")
        with open(self._config.get_secret_path()) as f:
            self._symkey = \
                self._crypto.decrypt_sym(
                    f.read(), passphrase=self._passphrase)
            self._crypto.symkey = self._symkey

    def _gen_symkey(self):
        """
        Generate a secret for symmetric encryption and store in a local
        encrypted file.
        """
        symkey = binascii.b2a_base64(os.urandom(self.SECRET_LENGTH))
        self._set_symkey(symkey)

    def _set_symkey(self, symkey):
        """
        Define and store the key to be used for symmetric encryption.

        @param symkey: the symmetric key
        @type symkey: str
        """
        if self._has_symkey():
            raise KeyAlreadyExists("Tried to set the value of the key for "
                                   "symmetric encryption but it already "
                                   "exists on disk.")
        self._symkey = symkey
        self._crypto.symkey = self._symkey
        self._store_symkey()

    def _store_symkey(self):
        ciphertext = self._crypto.encrypt_sym(
            self._symkey, self._passphrase)
        with open(self._config.get_secret_path(), 'w') as f:
            f.write(ciphertext)

    #-------------------------------------------------------------------------
    # General crypto utility methods.
    #-------------------------------------------------------------------------

    def _has_keys(self):
        """
        Return whether this instance has the key for symmetric encryption.

        @return: whether keys are available for this instance
        @rtype: bool
        """
        return self._has_symkey()

    def _load_keys(self):
        """
        Load the key for symmetric encryption from persistent storage.
        """
        self._load_symkey()

    def _gen_keys(self):
        """
        Generate a key for symmetric encryption.
        """
        self._gen_symkey()

    def _address_hash(self):
        """
        Calculate a hash for storing/retrieving key material on shared
        database, based on user's address.

        @return: the hash
        @rtype: str
        """
        return sha256('address-%s' % self._address).hexdigest()

    def _fetch_keys_from_shared_db(self):
        """
        Retrieve the document with encrypted key material from the shared
        database.

        @return: a document with encrypted key material in its contents
        @rtype: LeapDocument
        """
        events.signal(
            events.events_pb2.SOLEDAD_DOWNLOADING_KEYS, self._address)
        # TODO: change below to raise appropriate exceptions
        if not self._shared_db:
            return None
        doc = self._shared_db.get_doc_unauth(self._address_hash())
        events.signal(
            events.events_pb2.SOLEDAD_DONE_DOWNLOADING_KEYS, self._address)
        return doc

    def _assert_server_keys(self):
        """
        Assert our key copies are the same as server's ones.
        """
        assert self._has_keys()
        if not self._shared_db:
            return
        doc = self._fetch_keys_from_shared_db()
        if doc:
            remote_symkey = self.decrypt_sym(
                doc.content['_symkey'],
                passphrase=self._address_hash())
            assert remote_symkey == self._symkey
        else:
            events.signal(
                events.events_pb2.SOLEDAD_UPLOADING_KEYS, self._address)
            content = {
                '_symkey': self.encrypt_sym(self._symkey, self._passphrase),
            }
            doc = LeapDocument(doc_id=self._address_hash())
            doc.content = content
            self._shared_db.put_doc(doc)
            events.signal(
                events.events_pb2.SOLEDAD_DONE_UPLOADING_KEYS, self._address)

    #-------------------------------------------------------------------------
    # Document storage, retrieval and sync
    #-------------------------------------------------------------------------

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

    def sync(self, url, creds=None):
        """
        Synchronize the local encrypted replica with a remote replica.

        @param url: the url of the target replica to sync with
        @type url: str

        @return: the local generation before the synchronisation was
            performed.
        @rtype: str
        """
        # TODO: create authentication scheme for sync with server.
        local_gen = self._db.sync(url, creds=creds, autocreate=True)
        events.signal(events.events_pb2.SOLEDAD_DONE_DATA_SYNC, self._address)
        return local_gen

    def need_sync(self, url):
        """
        Return if local db replica differs from remote url's replica.

        @param url: The remote replica to compare with local replica.
        @type url: str

        @return: Whether remote replica and local replica differ.
        @rtype: bool
        """
        # TODO: create auth scheme for sync with server
        target = LeapSyncTarget(url, creds=None, crypto=self._crypto)
        info = target.get_sync_info(self._db._get_replica_uid())
        # compare source generation with target's last known source generation
        if self._db._get_generation() != info[4]:
            events.signal(
                events.events_pb2.SOLEDAD_NEW_DATA_TO_SYNC, self._address)
            return True
        return False

    #-------------------------------------------------------------------------
    # Recovery document export and import
    #-------------------------------------------------------------------------

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
            'address': self._address,
            'symkey': self._symkey,
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
        if self._has_keys():
            raise KeyAlreadyExists("You tried to import a recovery document "
                                   "but secret keys are already present.")
        if passphrase and not self._crypto.is_encrypted_sym(data):
            raise DocumentNotEncrypted("You provided a password but the "
                                       "recovery document is not encrypted.")
        if passphrase:
            data = self._crypto.decrypt_sym(data, passphrase=passphrase)
        data = json.loads(data)
        self._address = data['address']
        self._symkey = data['symkey']
        self._crypto.symkey = self._symkey
        self._store_symkey()
        # TODO: make this work well with bootstrap.
        self._load_keys()

    #
    # Setters/getters
    #

    def _get_address(self):
        return self._address

    address = property(_get_address, doc='The user address.')


__all__ = ['backends', 'util', 'server', 'shared_db']
