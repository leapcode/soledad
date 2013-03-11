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
                 initialize=True):
        """
        Bootstrap Soledad, initialize cryptographic material and open
        underlying U1DB database.
        """
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
        if self.shared_db_url:
            # TODO: eliminate need to create db here.
            self._shared_db = SoledadSharedDatabase.open_database(
                shared_db_url,
                True,
                token=auth_token)
        if initialize:
            self._bootstrap()

    def _bootstrap(self):
        """
        Bootstrap local Soledad instance.

        There are 3 stages for Soledad Client bootstrap:

            1. No key material has been generated, so we need to generate and
               upload to the server.

            2. Key material has already been generated and uploaded to the
               server, but has not been downloaded to this device/installation
               yet.

            3. Key material has already been generated and uploaded, and is
               also stored locally, so we just need to load it from disk.

        This method decides which bootstrap stage has to be performed and
        performs it.
        """
        # TODO: make sure key storage always happens (even if this method is
        #       interrupted).
        # TODO: write tests for bootstrap stages.
        self._init_dirs()
        self._gpg = GPGWrapper(gnupghome=self.gnupg_home)
        if not self._has_keys():
            try:
                # stage 2 bootstrap
                self._retrieve_keys()
            except Exception:
            # stage 1 bootstrap
                self._init_keys()
                # TODO: change key below
                self._send_keys(self._secret)
        # stage 3 bootstrap
        self._load_keys()
        self._send_keys(self._secret)
        self._init_db()

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
            for key in default_conf:
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
        if not self._has_openpgp_keypair():
            self._gen_openpgp_keypair()
        self._load_openpgp_keypair()
        # load/generate secret
        if not self._has_secret():
            self._gen_secret()
        self._load_secret()

    def _init_db(self):
        """
        Initialize the database for local storage .
        """
        # instantiate u1db
        # TODO: verify if secret for sqlcipher should be the same as the
        # one for symmetric encryption.
        self._db = sqlcipher.open(
            self.local_db_path,
            self._secret,
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

    def _has_secret(self):
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

    def _load_secret(self):
        """
        Load secret for symmetric encryption from local encrypted file.
        """
        if not self._has_secret():
            raise KeyDoesNotExist("Tried to load key for symmetric "
                                  "encryption but it does not exist on disk.")
        try:
            with open(self.secret_path) as f:
                self._secret = str(self._gpg.decrypt(f.read()))
        except IOError:
            raise IOError('Failed to open secret file %s.' % self.secret_path)

    def _gen_secret(self):
        """
        Generate a secret for symmetric encryption and store in a local
        encrypted file.
        """
        if self._has_secret():
            raise KeyAlreadyExists("Tried to generate secret for symmetric "
                                   "encryption but it already exists on "
                                   "disk.")
        self._secret = ''.join(
            random.choice(
                string.ascii_letters +
                string.digits) for x in range(self.SECRET_LENGTH))
        self._store_secret()

    def _store_secret(self):
        ciphertext = self._gpg.encrypt(self._secret, self._fingerprint,
                                       self._fingerprint)
        f = open(self.secret_path, 'w')
        f.write(str(ciphertext))
        f.close()

    #-------------------------------------------------------------------------
    # Management of OpenPGP keypair
    #-------------------------------------------------------------------------

    def _has_openpgp_keypair(self):
        """
        Verify if there exists an OpenPGP keypair for this user.
        """
        try:
            self._load_openpgp_keypair()
            return True
        except:
            return False

    def _gen_openpgp_keypair(self):
        """
        Generate an OpenPGP keypair for this user.
        """
        if self._has_openpgp_keypair():
            raise KeyAlreadyExists("Tried to generate OpenPGP keypair but it "
                                   "already exists on disk.")
        params = self._gpg.gen_key_input(
            key_type='RSA',
            key_length=4096,
            name_real=self._user_email,
            name_email=self._user_email,
            name_comment='Generated by LEAP Soledad.')
        self._gpg.gen_key(params)

    def _load_openpgp_keypair(self):
        """
        Find fingerprint for this user's OpenPGP keypair.
        """
        # TODO: verify if we have the corresponding private key.
        try:
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
        return self._has_openpgp_keypair() and self._has_secret()

    def _load_keys(self):
        self._load_openpgp_keypair()
        self._load_secret()

    def _gen_keys(self):
        self._gen_openpgp_keypair()
        self._gen_secret()

    def _user_hash(self):
        return hmac.new(self._user_email, 'user').hexdigest()

    def _retrieve_keys(self):
        return self._shared_db.get_doc_unauth(self._user_hash())
        # TODO: create corresponding error on server side

    def _send_keys(self, passphrase):
        # TODO: change this method's name to something more meaningful.
        privkey = self._gpg.export_keys(self._fingerprint, secret=True)
        content = {
            '_privkey': self.encrypt(privkey, passphrase=passphrase,
                                     symmetric=True),
            '_symkey': self.encrypt(self._secret),
        }
        doc = self._retrieve_keys()
        if not doc:
            doc = LeapDocument(doc_id=self._user_hash(), soledad=self)
        doc.content = content
        self._shared_db.put_doc(doc)

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

    def decrypt(self, data, passphrase=None, symmetric=False):
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
        return hmac.new(self._secret, doc_id).hexdigest()

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
            'secret': self._secret,
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
        self._load_openpgp_keypair()
        self._secret = data['secret']
        self._store_secret()
        # TODO: make this work well with bootstrap.
        self._load_keys()


__all__ = ['backends', 'util', 'server', 'shared_db']
