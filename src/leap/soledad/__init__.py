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
SyncTarget that encrypts data to the user's private OpenPGP key before
syncing, and (3) a CouchDB backend for remote storage in the server side.
"""

import os
import string
import random
import hmac
import configparser
import re
try:
    import simplejson as json
except ImportError:
    import json  # noqa


from leap.soledad.backends import sqlcipher
from leap.soledad.util import GPGWrapper
from leap.soledad.backends.leap_backend import (
    LeapDocument,
    DocumentNotEncrypted,
)
from leap.soledad.shared_db import SoledadSharedDatabase


class KeyDoesNotExist(Exception):
    """
    Soledad attempted to find a key that does not exist locally.
    """


class KeyAlreadyExists(Exception):
    """
    Soledad attempted to create a key that already exists locally.
    """


#-----------------------------------------------------------------------------
# Soledad: local encrypted storage and remote encrypted sync.
#-----------------------------------------------------------------------------

class Soledad(object):
    """
    Soledad provides encrypted data storage and sync.

    A Soledad instance is used to store and retrieve data in a local encrypted
    database and synchronize this database with Soledad server.

    This class is also responsible for bootstrapping users' account by
    creating OpenPGP keys and other cryptographic secrets and/or
    storing/fetching them on Soledad server.
    """

    # other configs
    SECRET_LENGTH = 50
    DEFAULT_CONF = {
        'gnupg_home': '%s/gnupg',
        'secret_path': '%s/secret.gpg',
        'local_db_path': '%s/soledad.u1db',
        'config_file': '%s/soledad.ini',
        'shared_db_url': '',
    }

    def __init__(self, user, prefix=None, gnupg_home=None,
                 secret_path=None, local_db_path=None,
                 config_file=None, shared_db_url=None, auth_token=None,
                 bootstrap=True):
        """
        Initialize configuration, cryptographic keys and dbs.

        @param user: Email address of the user (username@provider).
        @type user: str
        @param prefix: Path to use as prefix for files.
        @type prefix: str
        @param gnupg_home: Home directory for gnupg.
        @type gnupg_home: str
        @param secret_path: Path for storing gpg-encrypted key used for
            symmetric encryption.
        @type secret_path: str
        @param local_db_path: Path for local encrypted storage db.
        @type local_db_path: str
        @param config_file: Path for configuration file.
        @type config_file: str
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
        self._user = user
        self._auth_token = auth_token
        self._init_config(
            prefix=prefix,
            gnupg_home=gnupg_home,
            secret_path=secret_path,
            local_db_path=local_db_path,
            config_file=config_file,
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
        self._gpg = GPGWrapper(gnupghome=self.gnupg_home)
        # Stage 1 - Keys generation/loading
        if self._has_keys():
            self._load_keys()
        else:
            doc = self._get_keys_doc()
            if not doc:
                self._init_keys()
            else:
                self._set_privkey(self.decrypt(doc.content['_privkey'],
                                               passphrase=self._user_hash()))
                self._set_symkey(self.decrypt(doc.content['_symkey']))
        # Stage 2 - Keys synchronization
        self._assert_server_keys()
        # Stage 3 -Database initialization
        self._init_db()
        if self.shared_db_url:
            # TODO: eliminate need to create db here.
            self._shared_db = SoledadSharedDatabase.open_database(
                self.shared_db_url,
                True,
                token=auth_token)
        else:
            self._shared_db = None

    def _init_config(self, **kwargs):
        """
        Initialize configuration, with precedence order give by: instance
        parameters > config file > default values.

        @param kwargs: a dictionary with parameter values passed when
            instantiating this Soledad instance.
        @type kwargs: dict
        """
        # TODO: write tests for _init_config()
        self.prefix = kwargs['prefix'] or \
            os.environ['HOME'] + '/.config/leap/soledad'
        m = re.compile('.*%s.*')
        for key, default_value in self.DEFAULT_CONF.iteritems():
            val = kwargs[key] or default_value
            if m.match(val):
                val = val % self.prefix
            setattr(self, key, val)
        # get config from file
        # TODO: sanitize options from config file.
        config = configparser.ConfigParser()
        config.read(self.config_file)
        if 'soledad-client' in config:
            for key in self.DEFAULT_CONF:
                if key in config['soledad-client'] and not kwargs[key]:
                    setattr(self, key, config['soledad-client'][key])

    def _init_dirs(self):
        """
        Create work directories.
        """
        if not os.path.isdir(self.prefix):
            os.makedirs(self.prefix)

    def _init_keys(self):
        """
        Generate (if needed) and load OpenPGP keypair and secret for symmetric
        encryption.
        """
        # TODO: write tests for methods below.
        # load/generate OpenPGP keypair
        if not self._has_privkey():
            self._gen_privkey()
        self._load_privkey()
        # load/generate secret
        if not self._has_symkey():
            self._gen_symkey()
        self._load_symkey()

    def _init_db(self):
        """
        Initialize the database for local storage.
        """
        # instantiate u1db
        # TODO: verify if secret for sqlcipher should be the same as the
        # one for symmetric encryption.
        self._db = sqlcipher.open(
            self.local_db_path,
            self._symkey,
            create=True,
            document_factory=LeapDocument,
            soledad=self)

    def close(self):
        """
        Close underlying U1DB database.
        """
        self._db.close()

    #-------------------------------------------------------------------------
    # Management of secret for symmetric encryption
    #-------------------------------------------------------------------------

    # TODO: refactor the following methods to somewhere out of here
    # (a new class SoledadCrypto, maybe?)

    def _has_symkey(self):
        """
        Verify if a key for symmetric encryption exists in a local encrypted
        file.

        @return: whether this soledad instance has a key for symmetric
            encryption
        @rtype: bool
        """
        # does the file exist in disk?
        if not os.path.isfile(self.secret_path):
            return False
        # is it asymmetrically encrypted?
        f = open(self.secret_path, 'r')
        content = f.read()
        if not self.is_encrypted_asym(content):
            raise DocumentNotEncrypted(
                "File %s is not encrypted!" % self.secret_path)
        # can we decrypt it?
        fp = self._gpg.encrypted_to(content)['fingerprint']
        if fp != self._fingerprint:
            raise KeyDoesNotExist("Secret for symmetric encryption is "
                                  "encrypted to key with fingerprint '%s' "
                                  "which we don't have." % fp)
        return True

    def _load_symkey(self):
        """
        Load secret for symmetric encryption from local encrypted file.
        """
        if not self._has_symkey():
            raise KeyDoesNotExist("Tried to load key for symmetric "
                                  "encryption but it does not exist on disk.")
        try:
            with open(self.secret_path) as f:
                self._symkey = str(self._gpg.decrypt(f.read()))
        except IOError:
            raise IOError('Failed to open secret file %s.' % self.secret_path)

    def _gen_symkey(self):
        """
        Generate a secret for symmetric encryption and store in a local
        encrypted file.
        """
        self._set_symkey(''.join(
            random.choice(
                string.ascii_letters +
                string.digits) for x in range(self.SECRET_LENGTH)))

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
        self._store_symkey()

    def _store_symkey(self):
        ciphertext = self._gpg.encrypt(self._symkey, self._fingerprint,
                                       self._fingerprint)
        f = open(self.secret_path, 'w')
        f.write(str(ciphertext))
        f.close()

    #-------------------------------------------------------------------------
    # Management of OpenPGP keypair
    #-------------------------------------------------------------------------

    def _has_privkey(self):
        """
        Verify if there exists an OpenPGP keypair for this user.

        @return: whether this soledad instance has a private OpenPGP key
        @rtype: bool
        """
        try:
            self._load_privkey()
            return True
        except:
            return False

    def _gen_privkey(self):
        """
        Generate an OpenPGP keypair for the user.

        @return: the fingerprint of the generated key
        @rtype: str
        """
        if self._has_privkey():
            raise KeyAlreadyExists("Tried to generate OpenPGP keypair but it "
                                   "already exists on disk.")
        params = self._gpg.gen_key_input(
            key_type='RSA',
            key_length=4096,
            name_real=self._user,
            name_email=self._user,
            name_comment='Generated by LEAP Soledad.')
        fingerprint = self._gpg.gen_key(params).fingerprint
        return self._load_privkey(fingerprint)

    def _set_privkey(self, raw_data):
        """
        Set private OpenPGP key as the key to be used in this soledad instance.

        @param raw_data: the private key blob
        @type raw_data: str

        @return: the fingerprint of the key passed as argument
        @rtype: str
        """
        if self._has_privkey():
            raise KeyAlreadyExists("Tried to define an OpenPGP keypair but "
                                   "it already exists on disk.")
        fingerprint = self._gpg.import_keys(raw_data).fingerprints[0]
        return self._load_privkey(fingerprint)

    def _load_privkey(self, fingerprint=None):
        """
        Assert private key exists in local keyring and load its fingerprint to
        memory.

        This method either looks for a key with fingerprint given by the
        parameter or searches for a key bound to the user's email address if
        no finfgerprint is provided.

        Raises a LookupError if a key (either for the given fingerprint or for
        self._user if that was not provided) was not found.

        @param fingerprint: optional fingerprint for forcing a specific key to
            be loaded
        @type fingerprint: str

        @return: the fingerprint of the loaded key
        @rtype: str
        """
        # TODO: guarantee encrypted storage of private keys.
        try:
            if fingerprint:
                self._fingerprint = self._gpg.find_key_by_fingerprint(
                    fingerprint,
                    secret=True)['fingerprint']
            else:
                self._fingerprint = self._gpg.find_key_by_email(
                    self._user,
                    secret=True)['fingerprint']
            return self._fingerprint
        except LookupError:
            raise KeyDoesNotExist('OpenPGP private key but it does not exist '
                                  'on local keyring.')

    def publish_pubkey(self, keyserver):
        """
        Publish OpenPGP public key to a keyserver.

        @param keyserver: the keyserver url
        @type keyserver: str

        @return: whether the action succeeded
        @rtype: bool
        """
        # TODO: this has to talk to LEAP's Nickserver.
        pass

    #-------------------------------------------------------------------------
    # General crypto utility methods.
    #-------------------------------------------------------------------------

    def _has_keys(self):
        """
        Return whether this instance has both the private OpenPGP key and the
        key for symmetric encryption.

        @return: whether keys are available for this instance
        @rtype: bool
        """
        return self._has_privkey() and self._has_symkey()

    def _load_keys(self):
        """
        Load the OpenPGP private key and the key for symmetric encryption from
        persistent storage.
        """
        self._load_privkey()
        self._load_symkey()

    def _gen_keys(self):
        """
        Generate an OpenPGP keypair and a key for symmetric encryption.
        """
        self._gen_privkey()
        self._gen_symkey()

    def _user_hash(self):
        """
        Calculate a hash for storing/retrieving key material on shared
        database, based on user's email.

        @return: the hash
        @rtype: str
        """
        return hmac.new(self._user, 'user').hexdigest()

    def _get_keys_doc(self):
        """
        Retrieve the document with encrypted key material from the shared
        database.

        @return: a document with encrypted key material in its contents
        @rtype: LeapDocument
        """
        # TODO: change below to raise appropriate exceptions
        if not self._shared_db:
            return None
        return self._shared_db.get_doc_unauth(self._user_hash())

    def _assert_server_keys(self):
        """
        Assert our key copies are the same as server's ones.
        """
        assert self._has_keys()
        if not self._shared_db:
            return
        doc = self._get_keys_doc()
        if doc:
            remote_privkey = self.decrypt(doc.content['_privkey'],
                                          # TODO: change passphrase.
                                          passphrase=self._user_hash())
            remote_symkey = self.decrypt(doc.content['_symkey'])
            result = self._gpg.import_keys(remote_privkey)
            # TODO: is the following behaviour not expected in any scenario?
            assert result.fingerprints[0] == self._fingerprint
            assert remote_symkey == self._symkey
        else:
            privkey = self._gpg.export_keys(self._fingerprint, secret=True)
            content = {
                '_privkey': self.encrypt(privkey,
                                         # TODO: change passphrase
                                         passphrase=self._user_hash(),
                                         symmetric=True),
                '_symkey': self.encrypt(self._symkey),
            }
            doc = LeapDocument(doc_id=self._user_hash(), soledad=self)
            doc.content = content
            self._shared_db.put_doc(doc)

    def _assert_remote_keys(self):
        privkey, symkey = self._retrieve_keys()

    #-------------------------------------------------------------------------
    # Data encryption and decryption
    #-------------------------------------------------------------------------

    def encrypt(self, data, sign=None, passphrase=None, symmetric=False):
        """
        Encrypt data.

        @param data: the data to be encrypted
        @type data: str
        @param sign: the fingerprint of key to be used for signature
        @type sign: str
        @param passphrase: the passphrase to be used for encryption
        @type passphrase: str
        @param symmetric: whether the encryption scheme should be symmetric
        @type symmetric: bool

        @return: the encrypted data
        @rtype: str
        """
        return str(self._gpg.encrypt(data, self._fingerprint, sign=sign,
                                     passphrase=passphrase,
                                     symmetric=symmetric))

    def encrypt_symmetric(self, doc_id, data, sign=None):
        """
        Encrypt data using a password.

        The password is derived from the document id and the secret for
        symmetric encryption previously generated/loaded.

        @param doc_id: the document id
        @type doc_id: str
        @param data: the data to be encrypted
        @type data: str
        @param sign: the fingerprint of key to be used for signature
        @type sign: str

        @return: the encrypted data
        @rtype: str
        """
        return self.encrypt(data, sign=sign,
                            passphrase=self._hmac_passphrase(doc_id),
                            symmetric=True)

    def decrypt(self, data, passphrase=None):
        """
        Decrypt data.

        @param data: the data to be decrypted
        @type data: str
        @param passphrase: the passphrase to be used for decryption
        @type passphrase: str

        @return: the decrypted data
        @rtype: str
        """
        return str(self._gpg.decrypt(data, passphrase=passphrase))

    def decrypt_symmetric(self, doc_id, data):
        """
        Decrypt data using symmetric secret.

        @param doc_id: the document id
        @type doc_id: str
        @param data: the data to be decrypted
        @type data: str

        @return: the decrypted data
        @rtype: str
        """
        return self.decrypt(data, passphrase=self._hmac_passphrase(doc_id))

    def _hmac_passphrase(self, doc_id):
        """
        Generate a passphrase for symmetric encryption.

        The password is derived from the document id and the secret for
        symmetric encryption previously generated/loaded.

        @param doc_id: the document id
        @type doc_id: str

        @return: the passphrase
        @rtype: str
        """
        return hmac.new(self._symkey, doc_id).hexdigest()

    def is_encrypted(self, data):
        """
        Test whether some chunk of data is a cyphertext.

        @param data: the data to be tested
        @type data: str

        @return: whether the data is a cyphertext
        @rtype: bool
        """
        return self._gpg.is_encrypted(data)

    def is_encrypted_sym(self, data):
        """
        Test whether some chunk of data was encrypted with a symmetric key.

        @return: whether data is encrypted to a symmetric key
        @rtype: bool
        """
        return self._gpg.is_encrypted_sym(data)

    def is_encrypted_asym(self, data):
        """
        Test whether some chunk of data was encrypted to an OpenPGP private
        key.

        @return: whether data is encrypted to an OpenPGP private key
        @rtype: bool
        """
        return self._gpg.is_encrypted_asym(data)

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

    def sync(self, url):
        """
        Synchronize the local encrypted replica with a remote replica.

        @param url: the url of the target replica to sync with
        @type url: str

        @return: the local generation before the synchronisation was
            performed.
        @rtype: str
        """
        # TODO: create authentication scheme for sync with server.
        return self._db.sync(url, creds=None, autocreate=True)

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
            'user': self._user,
            'privkey': self._gpg.export_keys(self._fingerprint, secret=True),
            'symkey': self._symkey,
        })
        if passphrase:
            data = str(self._gpg.encrypt(data, None, sign=None,
                                         passphrase=passphrase,
                                         symmetric=True))
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
        if passphrase and not self._gpg.is_encrypted_sym(data):
            raise DocumentNotEncrypted("You provided a password but the "
                                       "recovery document is not encrypted.")
        if passphrase:
            data = str(self._gpg.decrypt(data, passphrase=passphrase))
        data = json.loads(data)
        self._user = data['user']
        self._gpg.import_keys(data['privkey'])
        self._load_privkey()
        self._symkey = data['symkey']
        self._store_symkey()
        # TODO: make this work well with bootstrap.
        self._load_keys()


__all__ = ['backends', 'util', 'server', 'shared_db']
