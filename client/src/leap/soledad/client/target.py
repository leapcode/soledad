# -*- coding: utf-8 -*-
# target.py
# Copyright (C) 2013, 2014 LEAP
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
import cStringIO
import gzip
import logging
import os
import re
import sqlite3
import urllib

from collections import defaultdict
from time import sleep

import simplejson as json
from taskthread import TimerTask
from u1db.remote import utils, http_errors
from u1db.errors import BrokenSyncStream
from u1db import errors
from u1db.remote.http_target import HTTPSyncTarget
from u1db.remote.http_client import _encode_query_parameter
from zope.proxy import ProxyBase
from zope.proxy import sameProxiedObjects, setProxiedObject

from leap.soledad.common.document import SoledadDocument
from leap.soledad.client.auth import TokenBasedAuth
from leap.soledad.client.crypto import is_symmetrically_encrypted
from leap.soledad.client.crypto import encrypt_docstr, decrypt_doc_dict
from leap.soledad.client.crypto import SyncEncrypterPool, SyncDecrypterPool

from leap.common.check import leap_check

logger = logging.getLogger(__name__)


def _gunzip(data):
    """
    Uncompress data that is gzipped.

    :param data: gzipped data
    :type data: basestring
    """
    buffer = cStringIO.StringIO()
    buffer.write(data)
    buffer.seek(0)
    try:
        data = gzip.GzipFile(mode='r', fileobj=buffer).read()
    except Exception:
        logger.warning("Error while decrypting gzipped data")
    buffer.close()
    return data


class PendingReceivedDocsSyncError(Exception):
    pass

#
# SoledadSyncTarget
#


class SoledadSyncTarget(HTTPSyncTarget, TokenBasedAuth):
    """
    A SyncTarget that encrypts data before sending and decrypts data after
    receiving.

    Normally encryption will have been written to the sync database upon
    document modification. The sync database is also used to write temporarily
    the parsed documents that the remote send us, before being decrypted and
    written to the main database.
    """

    # will later keep a reference to the insert-doc callback
    # passed to sync_exchange
    _insert_doc_cb = defaultdict(lambda: ProxyBase(None))

    #
    # Modified HTTPSyncTarget methods.
    #

    def __init__(self, url, creds=None, crypto=None, sync_db_path=None):
        """
        Initialize the SoledadSyncTarget.

        :param url: The url of the target replica to sync with.
        :type url: str

        :param creds: optional dictionary giving credentials.
                      to authorize the operation with the server.
        :type creds: dict

        :param soledad: An instance of Soledad so we can encrypt/decrypt
                        document contents when syncing.
        :type soledad: soledad.Soledad

        :param sync_db_path: Optional. Path to the db with the symmetric
                             encryption of the syncing documents. If
                             None, encryption will be done in-place,
                             instead of retreiving it from the dedicated
                             database.
        :type sync_db_path: str
        """
        HTTPSyncTarget.__init__(self, url, creds)
        self._crypto = crypto

        print "URL : ", url
        self.source_replica_uid = re.findall("user-([0-9a-fA-F]+)", url)[0]
        print "uid -->", self.source_replica_uid

        self._sync_db = None
        if sync_db_path is not None:
            self._init_sync_db(sync_db_path)

        # whether to bypass the received messages decryption deferral
        self._decrypt_inline = False

        # initialize syncing queue decryption pool
        self._sync_decr_pool = SyncDecrypterPool(
            self._crypto, self._sync_db,
            insert_doc_cb=self._insert_doc_cb)
        self._sync_watcher = TimerTask(
            self._decrypt_syncing_received_docs, delay=10)
        self._sync_watcher.start()

    def set_decrypt_inline(self, value):
        self._decrypt_inline = value

    @property
    def decrypt_inline(self):
        return self._decrypt_inline

    @staticmethod
    def connect(url, crypto=None):
        return SoledadSyncTarget(url, crypto=crypto)

    def _parse_sync_stream(self, data, return_doc_cb, ensure_callback=None):
        """
        Parse incoming synchronization stream and insert documents in the
        local database.

        If an incoming document's encryption scheme is equal to
        EncryptionSchemes.SYMKEY, then this method will decrypt it with
        Soledad's symmetric key.

        :param data: The body of the HTTP response.
        :type data: str

        :param return_doc_cb: A callback to insert docs from target.
        :type return_doc_cb: callable

        :param ensure_callback: A callback to ensure we have the correct
                                target_replica_uid, if it was just created.
        :type ensure_callback: callable

        :raise BrokenSyncStream: If `data` is malformed.

        :return: A dictionary representing the first line of the response got
                 from remote replica.
        :rtype: dict
        """
        # we keep a reference to the callback in case
        # we defer the decryption
        self._return_doc_cb = return_doc_cb

        parts = data.splitlines()  # one at a time
        if not parts or parts[0] != '[':
            raise BrokenSyncStream
        data = parts[1:-1]
        comma = False

        queue_for_decrypt = (not self.decrypt_inline or
                             self._sync_db is None)
        if queue_for_decrypt:
            self._sync_decr_pool.write_encrypted_lock.acquire()
        if data:
            line, comma = utils.check_and_strip_comma(data[0])
            res = json.loads(line)
            if ensure_callback and 'replica_uid' in res:
                ensure_callback(res['replica_uid'])

            # XXX check that writing_incoming lock is not acquired ---------

            for entry in data[1:]:
                if not comma:  # missing in between comma
                    raise BrokenSyncStream
                line, comma = utils.check_and_strip_comma(entry)
                entry = json.loads(line)
                gen, trans_id = entry['gen'], entry['trans_id']
                #-------------------------------------------------------------
                # symmetric decryption of document's contents
                #-------------------------------------------------------------
                # If arriving content was symmetrically encrypted, we decrypt
                # it. We do it inline if decrypt_inline flag is True or no
                # sync_db was defined, otherwise we defer it writing it to the
                # received docs table.

                doc = SoledadDocument(
                    entry['id'], entry['rev'], entry['content'])

                if is_symmetrically_encrypted(doc):
                    if queue_for_decrypt:
                        print "ENQUEUING DECRYPT -----------------------"
                        self._save_encrypted_received_doc(doc, gen, trans_id)
                    else:
                        print "INLINE DECRYPT -------------------------"
                        # force inline decrypt, or no-db fallback, for tests
                        key = self._crypto.doc_passphrase(doc.doc_id)
                        secret = self._crypto.secret
                        doc.set_json(decrypt_doc_dict(
                            doc.content, doc.doc_id, doc.rev,
                            key, secret))
                # XXX should release lock in the decrypt pool

                #-------------------------------------------------------------
                # end of symmetric decryption
                #-------------------------------------------------------------
                if not queue_for_decrypt:
                    return_doc_cb(doc, gen, trans_id)
        if queue_for_decrypt:
            self._sync_decr_pool.write_encrypted_lock.release()
        if parts[-1] != ']':
            try:
                partdic = json.loads(parts[-1])
            except ValueError:
                pass
            else:
                if isinstance(partdic, dict):
                    self._error(partdic)
            raise BrokenSyncStream
        if not data or comma:  # no entries or bad extra comma
            raise BrokenSyncStream
        return res

    def _request(self, method, url_parts, params=None, body=None,
                 content_type=None):
        """
        Overloaded method. See u1db docs.
        Patched for adding gzip encoding.
        """

        self._ensure_connection()
        unquoted_url = url_query = self._url.path
        if url_parts:
            if not url_query.endswith('/'):
                url_query += '/'
                unquoted_url = url_query
            url_query += '/'.join(urllib.quote(part, safe='')
                                  for part in url_parts)
            # oauth performs its own quoting
            unquoted_url += '/'.join(url_parts)
        encoded_params = {}
        if params:
            for key, value in params.items():
                key = unicode(key).encode('utf-8')
                encoded_params[key] = _encode_query_parameter(value)
            url_query += ('?' + urllib.urlencode(encoded_params))
        if body is not None and not isinstance(body, basestring):
            body = json.dumps(body)
            content_type = 'application/json'
        headers = {}
        if content_type:
            headers['content-type'] = content_type

        # Patched: We would like to receive gzip pretty please
        # ----------------------------------------------------
        headers['accept-encoding'] = "gzip"
        # ----------------------------------------------------

        headers.update(
            self._sign_request(method, unquoted_url, encoded_params))

        for delay in self._delays:
            try:
                self._conn.request(method, url_query, body, headers)
                return self._response()
            except errors.Unavailable, e:
                sleep(delay)
        raise e

    def _response(self):
        """
        Overloaded method, see u1db docs.
        We patched it for decrypting gzip content.
        """
        resp = self._conn.getresponse()
        body = resp.read()
        headers = dict(resp.getheaders())

        # Patched: We would like to decode gzip
        # ----------------------------------------------------
        encoding = headers.get('content-encoding', '')
        if "gzip" in encoding:
            body = _gunzip(body)
        # ----------------------------------------------------

        if resp.status in (200, 201):
            return body, headers
        elif resp.status in http_errors.ERROR_STATUSES:
            try:
                respdic = json.loads(body)
            except ValueError:
                pass
            else:
                self._error(respdic)
        # special case
        if resp.status == 503:
            raise errors.Unavailable(body, headers)
        raise errors.HTTPError(resp.status, body, headers)

    def sync_exchange(self, docs_by_generations, source_replica_uid,
                      last_known_generation, last_known_trans_id,
                      return_doc_cb, ensure_callback=None):
        """
        Find out which documents the remote database does not know about,
        encrypt and send them.

        This does the same as the parent's method but encrypts content before
        syncing.

        :param docs_by_generations: A list of (doc_id, generation, trans_id)
                                    of local documents that were changed since
                                    the last local generation the remote
                                    replica knows about.
        :type docs_by_generations: list of tuples

        :param source_replica_uid: The uid of the source replica.
        :type source_replica_uid: str

        :param last_known_generation: Target's last known generation.
        :type last_known_generation: int

        :param last_known_trans_id: Target's last known transaction id.
        :type last_known_trans_id: str

        :param return_doc_cb: A callback for inserting received documents from
                              target. If not overriden, this will call u1db
                              insert_doc_from_target in synchronizer, which
                              implements the TAKE OTHER semantics.
        :type return_doc_cb: function

        :param ensure_callback: A callback that ensures we know the target
                                replica uid if the target replica was just
                                created.
        :type ensure_callback: function

        :return: The new generation and transaction id of the target replica.
        :rtype: tuple
        """
        self.source_replica_uid = source_replica_uid
        print "SETTING SOURCE REPLICA UID to", source_replica_uid
        # let the decrypter pool access the passed callback to insert docs
        print "SETTING PROXY TO ------------>", return_doc_cb
        setProxiedObject(self._insert_doc_cb[source_replica_uid],
                         return_doc_cb)

        if not self.clear_to_sync():
            raise PendingReceivedDocsSyncError

        self._ensure_connection()
        if self._trace_hook:  # for tests
            self._trace_hook('sync_exchange')
        url = '%s/sync-from/%s' % (self._url.path, source_replica_uid)
        self._conn.putrequest('POST', url)
        self._conn.putheader('content-type', 'application/x-u1db-sync-stream')
        for header_name, header_value in self._sign_request('POST', url, {}):
            self._conn.putheader(header_name, header_value)
        self._conn.putheader('accept-encoding', 'gzip')
        entries = ['[']
        size = 1

        def prepare(**dic):
            entry = comma + '\r\n' + json.dumps(dic)
            entries.append(entry)
            return len(entry)

        comma = ''
        size += prepare(
            last_known_generation=last_known_generation,
            last_known_trans_id=last_known_trans_id,
            ensure=ensure_callback is not None)
        comma = ','

        synced = []
        for doc, gen, trans_id in docs_by_generations:
            # skip non-syncable docs
            if isinstance(doc, SoledadDocument) and not doc.syncable:
                continue
            #-------------------------------------------------------------
            # symmetric encryption of document's contents
            #-------------------------------------------------------------
            doc_json = doc.get_json()
            if not doc.is_tombstone():
                if self._sync_db is None:
                    # fallback case, for tests
                    key = self._crypto.doc_passphrase(doc.doc_id)
                    secret = self._crypto.secret

                    doc_json = encrypt_docstr(
                        json.dumps(doc.get_json()),
                        doc.doc_id, doc.rev, key, secret)
                else:
                    try:
                        doc_json = self.get_encrypted_doc_from_db(
                            doc.doc_id, doc.rev)
                    except Exception as exc:
                        logger.error("Error while getting "
                                     "encrypted doc from db")
                        logger.exception(exc)
                        continue
                    if doc_json is None:
                        # Not marked as tombstone, but we got nothing
                        # from the sync db. Maybe not encrypted yet.
                        continue
            #-------------------------------------------------------------
            # end of symmetric encryption
            #-------------------------------------------------------------
            size += prepare(id=doc.doc_id, rev=doc.rev,
                            content=doc_json,
                            gen=gen, trans_id=trans_id)
            synced.append((doc.doc_id, doc.rev))
        entries.append('\r\n]')
        size += len(entries[-1])
        self._conn.putheader('content-length', str(size))
        self._conn.endheaders()
        for entry in entries:
            self._conn.send(entry)
        entries = None
        data, headers = self._response()

        res = self._parse_sync_stream(data, return_doc_cb, ensure_callback)

        # delete documents from the sync queue
        self.delete_encrypted_docs_from_db(synced)

        data = None
        print "SYNC EXCHANGE FINISHED: new generation -> %s" % res['new_generation']
        return res['new_generation'], res['new_transaction_id']

    #
    # Token auth methods.
    #

    def set_token_credentials(self, uuid, token):
        """
        Store given credentials so we can sign the request later.

        :param uuid: The user's uuid.
        :type uuid: str
        :param token: The authentication token.
        :type token: str
        """
        TokenBasedAuth.set_token_credentials(self, uuid, token)

    def _sign_request(self, method, url_query, params):
        """
        Return an authorization header to be included in the HTTP request.

        :param method: The HTTP method.
        :type method: str
        :param url_query: The URL query string.
        :type url_query: str
        :param params: A list with encoded query parameters.
        :type param: list

        :return: The Authorization header.
        :rtype: list of tuple
        """
        return TokenBasedAuth._sign_request(self, method, url_query, params)

    #
    # Syncing db
    #

    def _init_sync_db(self, path):
        """
        Open a connection to the local db of encrypted docs for sync.

        :param path: The path to the local db.
        :type path: str
        """
        leap_check(path is not None, "Need a path to initialize db")
        if not os.path.isfile(path):
            logger.warning("Cannot open db: non-existent file!")
            return
        self._sync_db = sqlite3.connect(path, check_same_thread=False)

    def get_encrypted_doc_from_db(self, doc_id, doc_rev):
        """
        Retrieve encrypted document from the database of encrypted docs for
        sync.

        :param doc_id: The Document id.
        :type doc_id: str

        :param doc_rev: The document revision
        :type doc_rev: str
        """
        encr = SyncEncrypterPool
        c = self._sync_db.cursor()
        sql = ("SELECT content FROM %s WHERE doc_id=? and rev=?" % (
            encr.TABLE_NAME,))
        c.execute(sql, (doc_id, doc_rev))
        res = c.fetchall()
        if len(res) != 0:
            return res[0][0]

    def delete_encrypted_docs_from_db(self, docs_ids):
        """
        Delete several encrypted documents from the database of symmetrically
        encrypted docs to sync.

        :param docs_ids: an iterable with (doc_id, doc_rev) for all documents
                         to be deleted.
        :type docs_ids: any iterable of tuples of str
        """
        encr = SyncEncrypterPool
        c = self._sync_db.cursor()
        for doc_id, doc_rev in docs_ids:
            sql = ("DELETE FROM %s WHERE doc_id=? and rev=?" % (
                encr.TABLE_NAME,))
            c.execute(sql, (doc_id, doc_rev))
        self._sync_db.commit()

    def _save_encrypted_received_doc(self, doc, gen, trans_id):
        """
        Save an incoming document into the received docs table in the sync db.

        :param doc: The document to save.
        :type doc: SoledadDocument
        :param gen: The generation.
        :type gen: str
        :param  trans_id: Transacion id.
        :type gen: str
        """
        self._sync_decr_pool.insert_encrypted_received_doc(
            doc.doc_id, doc.rev, doc.content, gen, trans_id)

    #
    # Symmetric decryption of syncing docs
    #

    def clear_to_sync(self):
        """
        Return True if sync can proceed (ie, the received db table is empty).
        :rtype: bool
        """
        return self._sync_decr_pool.count_received_encrypted_docs() == 0

    def _decrypt_syncing_received_docs(self):
        """
        Decrypt the documents received from remote replica and insert them
        into the local one.

        Called periodically from TimerTask self._sync_watcher.
        """
        if sameProxiedObjects(self._insert_doc_cb.get(self.source_replica_uid),
                              None):
            logger.warning("No insert_doc callback, skipping decryption.")
            return

        decrypter = self._sync_decr_pool
        decrypter.decrypt_received_docs(self.source_replica_uid)
        decrypter.process_decrypted()
