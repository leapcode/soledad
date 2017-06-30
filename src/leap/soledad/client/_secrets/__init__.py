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

from leap.soledad.common.log import getLogger

from leap.soledad.client._secrets.storage import SecretsStorage
from leap.soledad.client._secrets.crypto import SecretsCrypto
from leap.soledad.client._secrets.util import emit, UserDataMixin
from leap.soledad.client import _scrypt


logger = getLogger(__name__)


class Secrets(UserDataMixin):

    lengths = {
        'remote_secret': 512,  # remote_secret is used to encrypt remote data.
        'local_salt': 64,      # local_salt is used in conjunction with
        'local_secret': 448,   # local_secret to derive a local_key for storage
    }

    def __init__(self, soledad):
        self._soledad = soledad
        self._secrets = {}
        self.crypto = SecretsCrypto(soledad)
        self.storage = SecretsStorage(soledad)
        self._bootstrap()

    #
    # bootstrap
    #

    def _bootstrap(self):

        # attempt to load secrets from local storage
        encrypted = self.storage.load_local()
        if encrypted:
            self._secrets = self.crypto.decrypt(encrypted)
            # maybe update the format of storage of local secret.
            if encrypted['version'] < self.crypto.VERSION:
                self.store_secrets()
            return

        # no secret was found in local storage, so this is a first run of
        # soledad for this user in this device. It is mandatory that we check
        # if there's a secret stored in server.
        encrypted = self.storage.load_remote()
        if encrypted:
            self._secrets = self.crypto.decrypt(encrypted)
            self.store_secrets()
            return

        # we have *not* found a secret neither in local nor in remote storage,
        # so we have to generate a new one, and then store it.
        self._secrets = self._generate()
        self.store_secrets()

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

    def store_secrets(self):
        # TODO: we have to improve the logic here, as we want to make sure that
        # whatever is stored locally should only be used after remote storage
        # is successful. Otherwise, this soledad could start encrypting with a
        # secret while another soledad in another device could start encrypting
        # with another secret, which would lead to decryption failures during
        # sync.
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
        return _scrypt.hash(
            self.local_secret,
            salt=self.local_salt,
            buflen=32,  # we need a key with 256 bits (32 bytes)
        )
