# -*- coding: utf-8 -*-
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

    # TODO: separate username from provider, currently in user_email.
    def __init__(self, user_email, prefix=None, gnupg_home=None,
                 secret_path=None, local_db_path=None,
                 config_file=None, shared_db_url=None, auth_token=None,
                 bootstrap=True):
        """
        Initialize configuration, cryptographic keys and dbs.

        :param user_email: Email address of the user (username@provider).
        :param prefix: Path to use as prefix for files.
        :param gnupg_home: Home directory for gnupg.
        :param secret_path: Path for storing gpg-encrypted key used for
            symmetric encryption.
        :param local_db_path: Path for local encrypted storage db.
        :param config_file: Path for configuration file.
        :param shared_db_url: URL for shared Soledad DB for key storage and
            unauth retrieval.
        :param auth_token: Authorization token for accessing remote databases.
        :param bootstrap: True/False, should bootstrap keys?
        """
        # TODO: allow for fingerprint enforcing.
        self._user_email = user_email
        self._auth_token = auth_token
        self._init_config(
            {'prefix': prefix,
             'gnupg_home': gnupg_home,
             'secret_path': secret_path,
             'local_db_path': local_db_path,
             'config_file': config_file,
             'shared_db_url': shared_db_url,
             }
        )
        if bootstrap:
            self._bootstrap()

    def _bootstrap(self):
        """
        Bootstrap local Soledad instance.

        Soledad Client bootstrap is the following sequence of stages:

            Stage 0 - Local environment setup.
                - directory initialization.
                - gnupg wrapper initialization.
            Stage 1 - Keys generation/loading:
                - if keys exists locally, load them.
                - else, if keys exists in server, download them.
                - else, generate keys.
            Stage 2 - Keys synchronization:
                - if keys exist in server, confirm we have the same keys
                  locally.
                - else, send keys to server.
            Stage 3 - Database initialization.

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

    def _init_config(self, param_conf):
        """
        Initialize configuration, with precedence order give by: instance
        parameters > config file > default values.
        """
        # TODO: write tests for _init_config()
        self.prefix = param_conf['prefix'] or \
            os.environ['HOME'] + '/.config/leap/soledad'
        m = re.compile('.*%s.*')
        for key, default_value in self.DEFAULT_CONF.iteritems():
            val = param_conf[key] or default_value
            if m.match(val):
                val = val % self.prefix
            setattr(self, key, val)
        # get config from file
        # TODO: sanitize options from config file.
        config = configparser.ConfigParser()
        config.read(self.config_file)
        if 'soledad-client' in config:
            for key in self.DEFAULT_CONF:
                if key in config['soledad-client'] and not param_conf[key]:
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
        Initialize the database for local storage .
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
    # (SoledadCrypto, maybe?)

    def _has_symkey(self):
        """
        Verify if secret for symmetric encryption exists in a local encrypted
        file.
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
        """
        try:
            self._load_privkey()
            return True
        except:
            return False

    def _gen_privkey(self):
        """
        Generate an OpenPGP keypair for this user.
        """
        if self._has_privkey():
            raise KeyAlreadyExists("Tried to generate OpenPGP keypair but it "
                                   "already exists on disk.")
        params = self._gpg.gen_key_input(
            key_type='RSA',
            key_length=4096,
            name_real=self._user_email,
            name_email=self._user_email,
            name_comment='Generated by LEAP Soledad.')
        fingerprint = self._gpg.gen_key(params).fingerprint
        return self._load_privkey(fingerprint)

    def _set_privkey(self, raw_data):
        if self._has_privkey():
            raise KeyAlreadyExists("Tried to generate OpenPGP keypair but it "
                                   "already exists on disk.")
        fingerprint = self._gpg.import_keys(raw_data).fingerprints[0]
        return self._load_privkey(fingerprint)

    def _load_privkey(self, fingerprint=None):
        """
        Find fingerprint for this user's OpenPGP keypair.
        """
        # TODO: guarantee encrypted storage of private keys.
        try:
            if fingerprint:
                self._fingerprint = self._gpg.find_key_by_fingerprint(
                    fingerprint,
                    secret=True)['fingerprint']
            else:
                self._fingerprint = self._gpg.find_key_by_email(
                    self._user_email,
                    secret=True)['fingerprint']
            return self._fingerprint
        except LookupError:
            raise KeyDoesNotExist("Tried to load OpenPGP keypair but it does "
                                  "not exist on disk.")

    def publish_pubkey(self, keyserver):
        """
        Publish OpenPGP public key to a keyserver.
        """
        # TODO: this has to talk to LEAP's Nickserver.
        pass

    #-------------------------------------------------------------------------
    # General crypto utility methods.
    #-------------------------------------------------------------------------

    def _has_keys(self):
        return self._has_privkey() and self._has_symkey()

    def _load_keys(self):
        self._load_privkey()
        self._load_symkey()

    def _gen_keys(self):
        self._gen_privkey()
        self._gen_symkey()

    def _user_hash(self):
        return hmac.new(self._user_email, 'user').hexdigest()

    def _get_keys_doc(self):
        return self._shared_db.get_doc_unauth(self._user_hash())

    def _assert_server_keys(self):
        """
        Assert our key copies are the same as server's ones.
        """
        assert self._has_keys()
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
        """
        return str(self._gpg.encrypt(data, self._fingerprint, sign=sign,
                                     passphrase=passphrase,
                                     symmetric=symmetric))

    def encrypt_symmetric(self, doc_id, data, sign=None):
        """
        Encrypt data using symmetric secret.
        """
        return self.encrypt(data, sign=sign,
                            passphrase=self._hmac_passphrase(doc_id),
                            symmetric=True)

    def decrypt(self, data, passphrase=None):
        """
        Decrypt data.
        """
        return str(self._gpg.decrypt(data, passphrase=passphrase))

    def decrypt_symmetric(self, doc_id, data):
        """
        Decrypt data using symmetric secret.
        """
        return self.decrypt(data, passphrase=self._hmac_passphrase(doc_id))

    def _hmac_passphrase(self, doc_id):
        return hmac.new(self._symkey, doc_id).hexdigest()

    def is_encrypted(self, data):
        return self._gpg.is_encrypted(data)

    def is_encrypted_sym(self, data):
        return self._gpg.is_encrypted_sym(data)

    def is_encrypted_asym(self, data):
        return self._gpg.is_encrypted_asym(data)

    #-------------------------------------------------------------------------
    # Document storage, retrieval and sync
    #-------------------------------------------------------------------------

    # TODO: refactor the following methods to somewhere out of here
    # (SoledadLocalDatabase, maybe?)

    def put_doc(self, doc):
        """
        Update a document in the local encrypted database.
        """
        return self._db.put_doc(doc)

    def delete_doc(self, doc):
        """
        Delete a document from the local encrypted database.
        """
        return self._db.delete_doc(doc)

    def get_doc(self, doc_id, include_deleted=False):
        """
        Retrieve a document from the local encrypted database.
        """
        return self._db.get_doc(doc_id, include_deleted=include_deleted)

    def get_docs(self, doc_ids, check_for_conflicts=True,
                 include_deleted=False):
        """
        Get the content for many documents.
        """
        return self._db.get_docs(doc_ids,
                                 check_for_conflicts=check_for_conflicts,
                                 include_deleted=include_deleted)

    def create_doc(self, content, doc_id=None):
        """
        Create a new document in the local encrypted database.
        """
        return self._db.create_doc(content, doc_id=doc_id)

    def get_doc_conflicts(self, doc_id):
        """
        Get the list of conflicts for the given document.
        """
        return self._db.get_doc_conflicts(doc_id)

    def resolve_doc(self, doc, conflicted_doc_revs):
        """
        Mark a document as no longer conflicted.
        """
        return self._db.resolve_doc(doc, conflicted_doc_revs)

    def sync(self, url):
        """
        Synchronize the local encrypted database with LEAP server.
        """
        # TODO: create authentication scheme for sync with server.
        return self._db.sync(url, creds=None, autocreate=True)

    #-------------------------------------------------------------------------
    # Recovery document export and import
    #-------------------------------------------------------------------------

    def export_recovery_document(self, passphrase):
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
        """
        data = json.dumps({
            'user_email': self._user_email,
            'privkey': self._gpg.export_keys(self._fingerprint, secret=True),
            'symkey': self._symkey,
        })
        if passphrase:
            data = str(self._gpg.encrypt(data, None, sign=None,
                                         passphrase=passphrase,
                                         symmetric=True))
        return data

    def import_recovery_document(self, data, passphrase):
        if self._has_keys():
            raise KeyAlreadyExists("You tried to import a recovery document "
                                   "but secret keys are already present.")
        if passphrase and not self._gpg.is_encrypted_sym(data):
            raise DocumentNotEncrypted("You provided a password but the "
                                       "recovery document is not encrypted.")
        if passphrase:
            data = str(self._gpg.decrypt(data, passphrase=passphrase))
        data = json.loads(data)
        self._user_email = data['user_email']
        self._gpg.import_keys(data['privkey'])
        self._load_privkey()
        self._symkey = data['symkey']
        self._store_symkey()
        # TODO: make this work well with bootstrap.
        self._load_keys()


__all__ = ['backends', 'util', 'server', 'shared_db']
