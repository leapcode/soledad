# -*- coding: utf-8 -*-
# _secrets/storage.py
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

import json
import six.moves.urllib.parse as urlparse

from hashlib import sha256

from leap.soledad.common import SHARED_DB_NAME
from leap.soledad.common.log import getLogger

from leap.soledad.client.shared_db import SoledadSharedDatabase
from leap.soledad.client._document import Document
from leap.soledad.client._secrets.util import emit, UserDataMixin


logger = getLogger(__name__)


class SecretsStorage(UserDataMixin):

    def __init__(self, soledad):
        self._soledad = soledad
        self._shared_db = self._soledad.shared_db or self._init_shared_db()
        self.__remote_doc = None

    @property
    def _creds(self):
        uuid = self._soledad.uuid
        token = self._soledad.token
        return {'token': {'uuid': uuid, 'token': token}}

    #
    # local storage
    #

    def load_local(self):
        path = self._soledad.secrets_path
        logger.info("trying to load secrets from disk: %s" % path)
        try:
            with open(path, 'r') as f:
                encrypted = json.loads(f.read())
            logger.info("secrets loaded successfully from disk")
            return encrypted
        except IOError:
            logger.warn("secrets not found in disk")
        return None

    def save_local(self, encrypted):
        path = self._soledad.secrets_path
        json_data = json.dumps(encrypted)
        with open(path, 'w') as f:
            f.write(json_data)

    #
    # remote storage
    #

    def _init_shared_db(self):
        url = urlparse.urljoin(self._soledad.server_url, SHARED_DB_NAME)
        creds = self._creds
        db = SoledadSharedDatabase.open_database(url, creds)
        return db

    def _remote_doc_id(self):
        passphrase = self._soledad.passphrase.encode('utf8')
        uuid = self._soledad.uuid
        text = '%s%s' % (passphrase, uuid)
        digest = sha256(text).hexdigest()
        return digest

    @property
    def _remote_doc(self):
        if not self.__remote_doc and self._shared_db:
            doc = self._get_remote_doc()
            self.__remote_doc = doc
        return self.__remote_doc

    @emit('downloading')
    def _get_remote_doc(self):
        logger.info('trying to load secrets from server...')
        doc = self._shared_db.get_doc(self._remote_doc_id())
        if doc:
            logger.info('secrets loaded successfully from server')
        else:
            logger.warn('secrets not found in server')
        return doc

    def load_remote(self):
        doc = self._remote_doc
        if not doc:
            return None
        encrypted = doc.content
        return encrypted

    @emit('uploading')
    def save_remote(self, encrypted):
        doc = self._remote_doc
        if not doc:
            doc = Document(doc_id=self._remote_doc_id())
        doc.content = encrypted
        db = self._shared_db
        if not db:
            logger.warn('no shared db found')
            return
        db.put_doc(doc)
