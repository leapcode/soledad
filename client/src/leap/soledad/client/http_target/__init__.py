# -*- coding: utf-8 -*-
# __init__.py
# Copyright (C) 2015 LEAP
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
A U1DB backend for encrypting data before sending to server and decrypting
after receiving.
"""


import logging

from leap.common.http import HTTPClient
from leap.soledad.client.http_target.send import HTTPDocSender
from leap.soledad.client.http_target.api import SyncTargetAPI
from leap.soledad.client.http_target.fetch import HTTPDocFetcher


logger = logging.getLogger(__name__)


class SoledadHTTPSyncTarget(SyncTargetAPI, HTTPDocSender, HTTPDocFetcher):

    """
    A SyncTarget that encrypts data before sending and decrypts data after
    receiving.

    Normally encryption will have been written to the sync database upon
    document modification. The sync database is also used to write temporarily
    the parsed documents that the remote send us, before being decrypted and
    written to the main database.
    """
    def __init__(self, url, source_replica_uid, creds, crypto, cert_file,
                 sync_db=None, sync_enc_pool=None):
        """
        Initialize the sync target.

        :param url: The server sync url.
        :type url: str
        :param source_replica_uid: The source replica uid which we use when
                                   deferring decryption.
        :type source_replica_uid: str
        :param creds: A dictionary containing the uuid and token.
        :type creds: creds
        :param crypto: An instance of SoledadCrypto so we can encrypt/decrypt
                        document contents when syncing.
        :type crypto: soledad.crypto.SoledadCrypto
        :param cert_file: Path to the certificate of the ca used to validate
                          the SSL certificate used by the remote soledad
                          server.
        :type cert_file: str
        :param sync_db: Optional. handler for the db with the symmetric
                        encryption of the syncing documents. If
                        None, encryption will be done in-place,
                        instead of retreiving it from the dedicated
                        database.
        :type sync_db: Sqlite handler
        :param sync_enc_pool: The encryption pool to use to defer encryption.
                              If None is passed the encryption will not be
                              deferred.
        :type sync_enc_pool: leap.soledad.client.encdecpool.SyncEncrypterPool
        """
        if url.endswith("/"):
            url = url[:-1]
        self._url = str(url) + "/sync-from/" + str(source_replica_uid)
        self.source_replica_uid = source_replica_uid
        self._auth_header = None
        self._uuid = None
        self.set_creds(creds)
        self._crypto = crypto
        self._sync_db = sync_db
        self._sync_enc_pool = sync_enc_pool
        self._insert_doc_cb = None
        # asynchronous encryption/decryption attributes
        self._decryption_callback = None
        self._sync_decr_pool = None

        # XXX Increasing timeout of simple requests to avoid chances of hitting
        # the duplicated syncing bug. This could be reduced to the 30s default
        # after implementing Cancellable Sync. See #7382
        self._http = HTTPClient(cert_file, timeout=90)
