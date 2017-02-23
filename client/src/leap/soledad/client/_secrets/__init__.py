# -*- coding: utf-8 -*-
# _secrets/__init__.py
# Copyright (C) 2016 LEAP
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

import os
import scrypt

from collections import namedtuple

from leap.soledad.common.log import getLogger

from leap.soledad.client._secrets.storage import SecretsStorage
from leap.soledad.client._secrets.crypto import SecretsCrypto
from leap.soledad.client._secrets.util import emit, EmitMixin


logger = getLogger(__name__)


SecretLength = namedtuple('SecretLength', 'name length')


class Secrets(EmitMixin):

    # remote secret is used

    lengths = {
        'remote_secret': 512,  # remote_secret is used to encrypt remote data.
        'local_salt': 64,      # local_salt is used in conjunction with
        'local_secret': 448,   # local_secret to derive a local_key for storage
    }

    def __init__(self, uuid, passphrase, url, local_path, get_token, userid,
                 shared_db=None):
        self._uuid = uuid
        self._passphrase = passphrase
        self._userid = userid
        self._secrets = {}
        self.crypto = SecretsCrypto(self.get_passphrase)
        self.storage = SecretsStorage(
            uuid, self.get_passphrase, url, local_path, get_token, userid,
            shared_db=shared_db)
        self._bootstrap()

    #
    # bootstrap
    #

    def _bootstrap(self):
        force_storage = False

        # attempt to load secrets from local storage
        encrypted = self.storage.load_local()

        # if not found, attempt to load secrets from remote storage
        if not encrypted:
            encrypted = self.storage.load_remote()

        if not encrypted:
            # if not found, generate new secrets
            secrets = self._generate()
            encrypted = self.crypto.encrypt(secrets)
            force_storage = True
        else:
            # decrypt secrets found either in local or remote storage
            secrets = self.crypto.decrypt(encrypted)

        self._secrets = secrets

        if encrypted['version'] < self.crypto.VERSION or force_storage:
            # TODO: what should we do if it's the first run and remote save
            #       fails?
            self.storage.save_local(encrypted)
            self.storage.save_remote(encrypted)

    #
    # generation
    #

    @emit('creating')
    def _generate(self):
        logger.info("generating new set of secrets...")
        secrets = {}
        for name, length in self.lengths.iteritems():
            secret = os.urandom(length)
            secrets[name] = secret
        logger.info("new set of secrets successfully generated")
        return secrets

    #
    # crypto
    #

    def _encrypt(self):
        # encrypt secrets
        secrets = self._secrets
        encrypted = self.crypto.encrypt(secrets)
        # create the recovery document
        data = {'secret': encrypted, 'version': 2}
        return data

    def get_passphrase(self):
        return self._passphrase.encode('utf-8')

    @property
    def passphrase(self):
        return self.get_passphrase()

    def change_passphrase(self, new_passphrase):
        self._passphrase = new_passphrase
        encrypted = self.crypto.encrypt(self._secrets)
        self.storage.save_local(encrypted)
        self.storage.save_remote(encrypted)

    #
    # secrets
    #

    @property
    def remote_secret(self):
        return self._secrets.get('remote_secret')

    @property
    def local_salt(self):
        return self._secrets.get('local_salt')

    @property
    def local_secret(self):
        return self._secrets.get('local_secret')

    @property
    def local_key(self):
        # local storage key is scrypt-derived from `local_secret` and
        # `local_salt` above
        secret = scrypt.hash(
            password=self.local_secret,
            salt=self.local_salt,
            buflen=32,  # we need a key with 256 bits (32 bytes)
        )
        return secret
