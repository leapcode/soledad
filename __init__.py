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
from leap.soledad.backends import sqlcipher
from leap.soledad.util import GPGWrapper
from leap.soledad.backends.leap_backend import (
    LeapDocument,
    DocumentNotEncrypted,
)


class KeyMissing(Exception):
    pass


class Soledad(object):
    """
    Soledad client class. It is used to store and fetch data locally in an
    encrypted manner and request synchronization with Soledad server. This
    class is also responsible for bootstrapping users' account by creating
    OpenPGP keys and other cryptographic secrets and/or storing/fetching them
    on Soledad server.
    """

    LOCAL_DB_PATH = None

    # other configs
    SECRET_LENGTH = 50

    def __init__(self, user_email, gnupghome=None, initialize=True,
                 prefix=None, secret_path=None, local_db_path=None):
        """
        Bootstrap Soledad, initialize cryptographic material and open
        underlying U1DB database.
        """
        self._user_email = user_email
        # paths
        self.PREFIX = prefix or os.environ['HOME'] + '/.config/leap/soledad'
        self.SECRET_PATH = secret_path or self.PREFIX + '/secret.gpg'
        self.LOCAL_DB_PATH = local_db_path or self.PREFIX + '/soledad.u1db'
        if not os.path.isdir(self.PREFIX):
            os.makedirs(self.PREFIX)
        self._gpg = GPGWrapper(
            gnupghome=(gnupghome or self.PREFIX + '/gnupg'))
        if initialize:
            self._init_crypto()
            self._init_db()

    def _init_crypto(self):
        """
        Load/generate OpenPGP keypair and secret for symmetric encryption.
        """
        # load/generate OpenPGP keypair
        if not self._has_openpgp_keypair():
            self._gen_openpgp_keypair()
        self._load_openpgp_keypair()
        # load/generate secret
        if not self._has_secret():
            self._gen_secret()
        self._load_secret()

    def _init_db(self):
        # instantiate u1db
        # TODO: verify if secret for sqlcipher should be the same as the
        # one for symmetric encryption.
        self._db = sqlcipher.open(
            self.LOCAL_DB_PATH,
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

    def _has_secret(self):
        """
        Verify if secret for symmetric encryption exists on local encrypted
        file.
        """
        # does the file exist in disk?
        if not os.path.isfile(self.SECRET_PATH):
            return False
        # is it asymmetrically encrypted?
        f = open(self.SECRET_PATH, 'r')
        content = f.read()
        if not self.is_encrypted_asym(content):
            raise DocumentNotEncrypted(
                "File %s is not encrypted!" % self.SECRET_PATH)
        # can we decrypt it?
        fp = self._gpg.encrypted_to(content)['fingerprint']
        if fp != self._fingerprint:
            raise KeyMissing("Key %s missing." % fp)
        return True

    def _load_secret(self):
        """
        Load secret for symmetric encryption from local encrypted file.
        """
        try:
            with open(self.SECRET_PATH) as f:
                self._secret = str(self._gpg.decrypt(f.read()))
        except IOError:
            raise IOError('Failed to open secret file %s.' % self.SECRET_PATH)

    def _gen_secret(self):
        """
        Generate a secret for symmetric encryption and store in a local
        encrypted file.
        """
        self._secret = ''.join(random.choice(string.ascii_uppercase +
                               string.digits) for x in
                               range(self.SECRET_LENGTH))
        ciphertext = self._gpg.encrypt(self._secret, self._fingerprint,
                                       self._fingerprint)
        f = open(self.SECRET_PATH, 'w')
        f.write(str(ciphertext))
        f.close()

    #-------------------------------------------------------------------------
    # Management of OpenPGP keypair
    #-------------------------------------------------------------------------

    def _has_openpgp_keypair(self):
        """
        Verify if there exists an OpenPGP keypair for this user.
        """
        # TODO: verify if we have the corresponding private key.
        try:
            self._gpg.find_key_by_email(self._user_email)
            return True
        except LookupError:
            return False

    def _gen_openpgp_keypair(self):
        """
        Generate an OpenPGP keypair for this user.
        """
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
        self._fingerprint = self._gpg.find_key_by_email(
            self._user_email)['fingerprint']

    def publish_pubkey(self, keyserver):
        """
        Publish OpenPGP public key to a keyserver.
        """
        # TODO: this has to talk to LEAP's Nickserver.
        pass

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

__all__ = ['util']
