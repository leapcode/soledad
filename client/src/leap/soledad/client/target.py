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
import re
import urllib
import threading
import urlparse

from collections import defaultdict
from time import sleep
from uuid import uuid4
from contextlib import contextmanager

import simplejson as json
from taskthread import TimerTask
from u1db import errors
from u1db.remote import utils, http_errors
from u1db.remote.http_target import HTTPSyncTarget
from u1db.remote.http_client import _encode_query_parameter, HTTPClientBase
from zope.proxy import ProxyBase
from zope.proxy import sameProxiedObjects, setProxiedObject

from leap.soledad.common import soledad_assert
from leap.soledad.common.document import SoledadDocument
from leap.soledad.client.auth import TokenBasedAuth
from leap.soledad.client.crypto import is_symmetrically_encrypted
from leap.soledad.client.crypto import encrypt_doc, decrypt_doc
from leap.soledad.client.crypto import SyncEncrypterPool, SyncDecrypterPool
from leap.soledad.client.events import SOLEDAD_SYNC_SEND_STATUS
from leap.soledad.client.events import SOLEDAD_SYNC_RECEIVE_STATUS
from leap.soledad.client.events import signal


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


class DocumentSyncerThread(threading.Thread):
    """
    A thread that knowns how to either send or receive a document during the
    sync process.
    """

    def __init__(self, doc_syncer, release_method, failed_method,
            idx, total, last_request_lock=None, last_callback_lock=None):
        """
        Initialize a new syncer thread.

        :param doc_syncer: A document syncer.
        :type doc_syncer: HTTPDocumentSyncer
        :param release_method: A method to be called when finished running.
        :type release_method: callable(DocumentSyncerThread)
        :param failed_method: A method to be called when we failed.
        :type failed_method: callable(DocumentSyncerThread)
        :param idx: The index count of the current operation.
        :type idx: int
        :param total: The total number of operations.
        :type total: int
        :param last_request_lock: A lock to wait for before actually performing
                                  the request.
        :type last_request_lock: threading.Lock
        :param last_callback_lock: A lock to wait for before actually running
                                  the success callback.
        :type last_callback_lock: threading.Lock
        """
        threading.Thread.__init__(self)
        self._doc_syncer = doc_syncer
        self._release_method = release_method
        self._failed_method = failed_method
        self._idx = idx
        self._total = total
        self._last_request_lock = last_request_lock
        self._last_callback_lock = last_callback_lock
        self._response = None
        self._exception = None
        self._result = None
        self._success = False
        # a lock so we can signal when we're finished
        self._request_lock = threading.Lock()
        self._request_lock.acquire()
        self._callback_lock = threading.Lock()
        self._callback_lock.acquire()
        # make thread interruptable
        self._stopped = None
        self._stop_lock = threading.Lock()

    def run(self):
        """
        Run the HTTP request and store results.

        This method will block and wait for an eventual previous operation to
        finish before actually performing the request. It also traps any
        exception and register any failure with the request.
        """
        with self._stop_lock:
            if self._stopped is None:
                self._stopped = False
            else:
                return

        # eventually wait for the previous thread to finish
        if self._last_request_lock is not None:
            self._last_request_lock.acquire()

        # bail out in case we've been interrupted
        if self.stopped is True:
            return

        try:
            self._response = self._doc_syncer.do_request()
            self._request_lock.release()

            # run success callback
            if self._doc_syncer.success_callback is not None:

                # eventually wait for callback lock release
                if self._last_callback_lock is not None:
                    self._last_callback_lock.acquire()

                # bail out in case we've been interrupted
                if self._stopped is True:
                    return

                self._result = self._doc_syncer.success_callback(
                    self._idx, self._total, self._response)
                self._success = True
                doc_syncer = self._doc_syncer
                self._release_method(self, doc_syncer)
                self._doc_syncer = None
                # let next thread executed its callback
                self._callback_lock.release()

        # trap any exception and signal failure
        except Exception as e:
            self._exception = e
            self._success = False
            # run failure callback
            if self._doc_syncer.failure_callback is not None:

                # eventually wait for callback lock release
                if self._last_callback_lock is not None:
                    self._last_callback_lock.acquire()

                # bail out in case we've been interrupted
                if self.stopped is True:
                    return

                self._doc_syncer.failure_callback(
                    self._idx, self._total, self._exception)

                self._failed_method(self)
                # we do not release the callback lock here because we
                # failed and so we don't want other threads to succeed.

    @property
    def doc_syncer(self):
        return self._doc_syncer

    @property
    def response(self):
        return self._response

    @property
    def exception(self):
        return self._exception

    @property
    def callback_lock(self):
        return self._callback_lock

    @property
    def request_lock(self):
        return self._request_lock

    @property
    def success(self):
        return self._success

    def stop(self):
        with self._stop_lock:
            self._stopped = True

    @property
    def stopped(self):
        with self._stop_lock:
            return self._stopped

    @property
    def result(self):
        return self._result


class DocumentSyncerPool(object):
    """
    A pool of reusable document syncers.
    """

    POOL_SIZE = 10
    """
    The maximum amount of syncer threads running at the same time.
    """

    def __init__(self, raw_url, raw_creds, query_string, headers,
            ensure_callback, stop_method):
        """
        Initialize the document syncer pool.

        :param raw_url: The complete raw URL for the HTTP request.
        :type raw_url: str
        :param raw_creds: The credentials for the HTTP request.
        :type raw_creds: dict
        :param query_string: The query string for the HTTP request.
        :type query_string: str
        :param headers: The headers for the HTTP request.
        :type headers: dict
        :param ensure_callback: A callback to ensure we have the correct
                                target_replica_uid, if it was just created.
        :type ensure_callback: callable

        """
        # save syncer params
        self._raw_url = raw_url
        self._raw_creds = raw_creds
        self._query_string = query_string
        self._headers = headers
        self._ensure_callback = ensure_callback
        self._stop_method = stop_method
        # pool attributes
        self._failures = False
        self._semaphore_pool = threading.BoundedSemaphore(
            DocumentSyncerPool.POOL_SIZE)
        self._pool_access_lock = threading.Lock()
        self._doc_syncers = []
        self._threads = []

    def new_syncer_thread(self, idx, total, last_request_lock=None,
            last_callback_lock=None):
        """
        Yield a new document syncer thread.

        :param idx: The index count of the current operation.
        :type idx: int
        :param total: The total number of operations.
        :type total: int
        :param last_request_lock: A lock to wait for before actually performing
                                  the request.
        :type last_request_lock: threading.Lock
        :param last_callback_lock: A lock to wait for before actually running
                                   the success callback.
        :type last_callback_lock: threading.Lock
        """
        t = None
        # wait for available threads
        self._semaphore_pool.acquire()
        with self._pool_access_lock:
            if self._failures is True:
                return None
            # get a syncer
            doc_syncer = self._get_syncer()
            # we rely on DocumentSyncerThread.run() to release the lock using
            # self.release_syncer so we can launch a new thread.
            t = DocumentSyncerThread(
                doc_syncer, self.release_syncer, self.cancel_threads,
                idx, total,
                last_request_lock=last_request_lock,
                last_callback_lock=last_callback_lock)
            self._threads.append(t)
            return t

    def _failed(self):
        with self._pool_access_lock:
            self._failures = True

    @property
    def failures(self):
        return self._failures

    def _get_syncer(self):
        """
        Get a document syncer from the pool.

        This method will create a new syncer whenever there is no syncer
        available in the pool.

        :return: A syncer.
        :rtype: HTTPDocumentSyncer
        """
        syncer = None
        # get an available syncer or create a new one
        try:
            syncer = self._doc_syncers.pop()
        except IndexError:
            syncer = HTTPDocumentSyncer(
                self._raw_url, self._raw_creds, self._query_string,
                self._headers, self._ensure_callback)
        return syncer

    def release_syncer(self, syncer_thread, doc_syncer):
        """
        Return a syncer to the pool after use and check for any failures.

        :param syncer: The syncer to be returned to the pool.
        :type syncer: HTTPDocumentSyncer
        """
        with self._pool_access_lock:
            self._doc_syncers.append(doc_syncer)
            if syncer_thread.success is True:
                self._threads.remove(syncer_thread)
            self._semaphore_pool.release()

    def cancel_threads(self, calling_thread):
        """
        Stop all threads in the pool.
        """
        # stop sync
        self._stop_method()
        stopped = []
        # stop all threads
        logger.warning("Soledad sync: cancelling sync threads...")
        with self._pool_access_lock:
            self._failures = True
            while self._threads:
                t = self._threads.pop(0)
                t.stop()
                self._doc_syncers.append(t.doc_syncer)
                stopped.append(t)
        # release locks and join
        while stopped:
            t = stopped.pop(0)
            t.request_lock.acquire(False)   # just in case
            t.request_lock.release()
            t.callback_lock.acquire(False)  # just in case
            t.callback_lock.release()
        # release any blocking semaphores
        for i in xrange(DocumentSyncerPool.POOL_SIZE):
            try:
                self._semaphore_pool.release()
            except ValueError:
                break
        logger.warning("Soledad sync: cancelled sync threads.")

    def cleanup(self):
        """
        Close and remove any syncers from the pool.
        """
        with self._pool_access_lock:
            while self._doc_syncers:
                syncer = self._doc_syncers.pop()
                syncer.close()
                del syncer


class HTTPDocumentSyncer(HTTPClientBase, TokenBasedAuth):

    def __init__(self, raw_url, creds, query_string, headers, ensure_callback):
        """
        Initialize the client.

        :param raw_url: The raw URL of the target HTTP server.
        :type raw_url: str
        :param creds: Authentication credentials.
        :type creds: dict
        :param query_string: The query string for the HTTP request.
        :type query_string: str
        :param headers: The headers for the HTTP request.
        :type headers: dict
        :param ensure_callback: A callback to ensure we have the correct
                                target_replica_uid, if it was just created.
        :type ensure_callback: callable
        """
        HTTPClientBase.__init__(self, raw_url, creds=creds)
        # info needed to perform the request
        self._query_string = query_string
        self._headers = headers
        self._ensure_callback = ensure_callback
        # the actual request method
        self._request_method = None
        self._success_callback = None
        self._failure_callback = None

    def _reset(self):
        """
        Reset this document syncer so we can reuse it.
        """
        self._request_method = None
        self._success_callback = None
        self._failure_callback = None
        self._request_method = None

    def set_request_method(self, method, *args, **kwargs):
        """
        Set the actual method to perform the request.

        :param method: Either 'get' or 'put'.
        :type method: str
        :param args: Arguments for the request method.
        :type args: list
        :param kwargs: Keyworded arguments for the request method.
        :type kwargs: dict
        """
        self._reset()
        # resolve request method
        if method is 'get':
            self._request_method = self._get_doc
        elif method is 'put':
            self._request_method = self._put_doc
        else:
            raise Exception
        # store request method args
        self._args = args
        self._kwargs = kwargs

    def set_success_callback(self, callback):
        self._success_callback = callback

    def set_failure_callback(self, callback):
        self._failure_callback = callback

    @property
    def success_callback(self):
        return self._success_callback

    @property
    def failure_callback(self):
        return self._failure_callback

    def do_request(self):
        """
        Actually perform the request.

        :return: The body and headers of the response.
        :rtype: tuple
        """
        self._ensure_connection()
        args = self._args
        kwargs = self._kwargs
        return self._request_method(*args, **kwargs)

    def _request(self, method, url_parts, params=None, body=None,
                 content_type=None):
        """
        Perform an HTTP request.

        :param method: The HTTP request method.
        :type method: str
        :param url_parts: A list representing the request path.
        :type url_parts: list
        :param params: Parameters for the URL query string.
        :type params: dict
        :param body: The body of the request.
        :type body: str
        :param content-type: The content-type of the request.
        :type content-type: str

        :return: The body and headers of the response.
        :rtype: tuple

        :raise errors.Unavailable: Raised after a number of unsuccesful
                                   request attempts.
        :raise Exception: Raised for any other exception ocurring during the
                          request.
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
        Return the response of the (possibly gzipped) HTTP request.

        :return: The body and headers of the response.
        :rtype: tuple
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

    def _prepare(self, comma, entries, **dic):
        """
        Prepare an entry to be sent through a syncing POST request.

        :param comma: A string to be prepended to the current entry.
        :type comma: str
        :param entries: A list of entries accumulated to be sent on the
                        request.
        :type entries: list
        :param dic: The data to be included in this entry.
        :type dic: dict

        :return: The size of the prepared entry.
        :rtype: int
        """
        entry = comma + '\r\n' + json.dumps(dic)
        entries.append(entry)
        return len(entry)

    def _init_post_request(self, action, content_length):
        """
        Initiate a syncing POST request.

        :param url: The syncing URL.
        :type url: str
        :param action: The syncing action, either 'get' or 'receive'.
        :type action: str
        :param headers: The initial headers to be sent on this request.
        :type headers: dict
        :param content_length: The content-length of the request.
        :type content_length: int
        """
        self._conn.putrequest('POST', self._query_string)
        self._conn.putheader(
            'content-type', 'application/x-soledad-sync-%s' % action)
        for header_name, header_value in self._headers:
            self._conn.putheader(header_name, header_value)
        self._conn.putheader('accept-encoding', 'gzip')
        self._conn.putheader('content-length', str(content_length))
        self._conn.endheaders()

    def _get_doc(self, received, sync_id, last_known_generation,
            last_known_trans_id):
        """
        Get a sync document from server by means of a POST request.

        :param received: The number of documents already received in the
                         current sync session.
        :type received: int
        :param sync_id: The id for the current sync session.
        :type sync_id: str
        :param last_known_generation: Target's last known generation.
        :type last_known_generation: int
        :param last_known_trans_id: Target's last known transaction id.
        :type last_known_trans_id: str

        :return: The body and headers of the response.
        :rtype: tuple
        """
        entries = ['[']
        size = 1
        # add remote replica metadata to the request
        size += self._prepare(
            '', entries,
            last_known_generation=last_known_generation,
            last_known_trans_id=last_known_trans_id,
            sync_id=sync_id,
            ensure=self._ensure_callback is not None)
        # inform server of how many documents have already been received
        size += self._prepare(
            ',', entries, received=received)
        entries.append('\r\n]')
        size += len(entries[-1])
        # send headers
        self._init_post_request('get', size)
        # get document
        for entry in entries:
            self._conn.send(entry)
        return self._response()

    def _put_doc(self, sync_id, last_known_generation, last_known_trans_id,
            id, rev, content, gen, trans_id, number_of_docs, doc_idx):
        """
        Put a sync document on server by means of a POST request.

        :param sync_id: The id for the current sync session.
        :type sync_id: str
        :param last_known_generation: Target's last known generation.
        :type last_known_generation: int
        :param last_known_trans_id: Target's last known transaction id.
        :type last_known_trans_id: str
        :param id: The document id.
        :type id: str
        :param rev: The document revision.
        :type rev: str
        :param content: The serialized document content.
        :type content: str
        :param gen: The generation of the modification of the document.
        :type gen: int
        :param trans_id: The transaction id of the modification of the
                         document.
        :type trans_id: str
        :param number_of_docs: The total amount of documents sent on this sync
                               session.
        :type number_of_docs: int
        :param doc_idx: The index of the current document being sent.
        :type doc_idx: int

        :return: The body and headers of the response.
        :rtype: tuple
        """
        # prepare to send the document
        entries = ['[']
        size = 1
        # add remote replica metadata to the request
        size += self._prepare(
            '', entries,
            last_known_generation=last_known_generation,
            last_known_trans_id=last_known_trans_id,
            sync_id=sync_id,
            ensure=self._ensure_callback is not None)
        # add the document to the request
        size += self._prepare(
            ',', entries,
            id=id, rev=rev, content=content, gen=gen, trans_id=trans_id,
            number_of_docs=number_of_docs, doc_idx=doc_idx)
        entries.append('\r\n]')
        size += len(entries[-1])
        # send headers
        self._init_post_request('put', size)
        # send document
        for entry in entries:
            self._conn.send(entry)
        return self._response()

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

    def set_token_credentials(self, uuid, token):
        """
        Store given credentials so we can sign the request later.

        :param uuid: The user's uuid.
        :type uuid: str
        :param token: The authentication token.
        :type token: str
        """
        TokenBasedAuth.set_token_credentials(self, uuid, token)


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

    """
    Period of recurrence of the periodic decrypting task, in seconds.
    """
    DECRYPT_TASK_PERIOD = 0.5

    #
    # Modified HTTPSyncTarget methods.
    #

    def __init__(self, url, source_replica_uid=None, creds=None, crypto=None,
            sync_db=None, sync_db_write_lock=None):
        """
        Initialize the SoledadSyncTarget.

        :param source_replica_uid: The source replica uid which we use when
                                   deferring decryption.
        :type source_replica_uid: str
        :param url: The url of the target replica to sync with.
        :type url: str
        :param creds: Optional dictionary giving credentials.
                      to authorize the operation with the server.
        :type creds: dict
        :param crypto: An instance of SoledadCrypto so we can encrypt/decrypt
                        document contents when syncing.
        :type crypto: soledad.crypto.SoledadCrypto
        :param sync_db: Optional. handler for the db with the symmetric
                        encryption of the syncing documents. If
                        None, encryption will be done in-place,
                        instead of retreiving it from the dedicated
                        database.
        :type sync_db: Sqlite handler
        :param sync_db_write_lock: a write lock for controlling concurrent
                                   access to the sync_db
        :type sync_db_write_lock: threading.Lock
        """
        HTTPSyncTarget.__init__(self, url, creds)
        self._raw_url = url
        self._raw_creds = creds
        self._crypto = crypto
        self._stopped = True
        self._stop_lock = threading.Lock()
        self._sync_exchange_lock = threading.Lock()
        self.source_replica_uid = source_replica_uid
        self._defer_decryption = False

        # deferred decryption attributes
        self._sync_db = None
        self._sync_db_write_lock = None
        self._decryption_callback = None
        self._sync_decr_pool = None
        self._sync_watcher = None
        if sync_db and sync_db_write_lock is not None:
            self._sync_db = sync_db
            self._sync_db_write_lock = sync_db_write_lock

    def _setup_sync_decr_pool(self, last_known_generation):
        """
        Set up the SyncDecrypterPool for deferred decryption.

        :param last_known_generation: Target's last known generation.
        :type last_known_generation: int
        """
        if self._sync_decr_pool is None:
            # initialize syncing queue decryption pool
            self._sync_decr_pool = SyncDecrypterPool(
                self._crypto, self._sync_db,
                self._sync_db_write_lock,
                insert_doc_cb=self._insert_doc_cb)
            self._sync_decr_pool.set_source_replica_uid(
                self.source_replica_uid)

    def _teardown_sync_decr_pool(self):
        """
        Tear down the SyncDecrypterPool.
        """
        if self._sync_decr_pool is not None:
            self._sync_decr_pool.close()
            self._sync_decr_pool = None

    def _setup_sync_watcher(self):
        """
        Set up the sync watcher for deferred decryption.
        """
        if self._sync_watcher is None:
            self._sync_watcher = TimerTask(
                self._decrypt_syncing_received_docs,
                delay=self.DECRYPT_TASK_PERIOD)

    def _teardown_sync_watcher(self):
        """
        Tear down the sync watcher.
        """
        if self._sync_watcher is not None:
            self._sync_watcher.stop()
            self._sync_watcher.shutdown()
            self._sync_watcher = None

    def _get_replica_uid(self, url):
        """
        Return replica uid from the url, or None.

        :param url: the replica url
        :type url: str
        """
        replica_uid_match = re.findall("user-([0-9a-fA-F]+)", url)
        return replica_uid_match[0] if len(replica_uid_match) > 0 else None

    @staticmethod
    def connect(url, source_replica_uid=None, crypto=None):
        return SoledadSyncTarget(
            url, source_replica_uid=source_replica_uid, crypto=crypto)

    def _parse_received_doc_response(self, response):
        """
        Parse the response from the server containing the received document.

        :param response: The body and headers of the response.
        :type response: tuple(str, dict)
        """
        data, _ = response
        # decode incoming stream
        parts = data.splitlines()
        if not parts or parts[0] != '[' or parts[-1] != ']':
            raise errors.BrokenSyncStream
        data = parts[1:-1]
        # decode metadata
        line, comma = utils.check_and_strip_comma(data[0])
        metadata = None
        try:
            metadata = json.loads(line)
            new_generation = metadata['new_generation']
            new_transaction_id = metadata['new_transaction_id']
            number_of_changes = metadata['number_of_changes']
        except (json.JSONDecodeError, KeyError):
            raise errors.BrokenSyncStream
        # make sure we have replica_uid from fresh new dbs
        if self._ensure_callback and 'replica_uid' in metadata:
            self._ensure_callback(metadata['replica_uid'])
        # parse incoming document info
        doc_id = None
        rev = None
        content = None
        gen = None
        trans_id = None
        if number_of_changes > 0:
            try:
                entry = json.loads(data[1])
                doc_id = entry['id']
                rev = entry['rev']
                content = entry['content']
                gen = entry['gen']
                trans_id = entry['trans_id']
            except (IndexError, KeyError):
                raise errors.BrokenSyncStream
        return new_generation, new_transaction_id, number_of_changes, \
            doc_id, rev, content, gen, trans_id

    def _insert_received_doc(self, idx, total, response):
        """
        Insert a received document into the local replica.

        :param idx: The index count of the current operation.
        :type idx: int
        :param total: The total number of operations.
        :type total: int
        :param response: The body and headers of the response.
        :type response: tuple(str, dict)
        """
        new_generation, new_transaction_id, number_of_changes, doc_id, \
            rev, content, gen, trans_id = \
                self._parse_received_doc_response(response)
        if doc_id is not None:
            # decrypt incoming document and insert into local database
            # -------------------------------------------------------------
            # symmetric decryption of document's contents
            # -------------------------------------------------------------
            # If arriving content was symmetrically encrypted, we decrypt it.
            # We do it inline if defer_decryption flag is False or no sync_db
            # was defined, otherwise we defer it writing it to the received
            # docs table.
            doc = SoledadDocument(doc_id, rev, content)
            if is_symmetrically_encrypted(doc):
                if self._queue_for_decrypt:
                    self._save_encrypted_received_doc(
                        doc, gen, trans_id, idx, total)
                else:
                    # defer_decryption is False or no-sync-db fallback
                    doc.set_json(decrypt_doc(self._crypto, doc))
                    self._return_doc_cb(doc, gen, trans_id)
            else:
                # not symmetrically encrypted doc, insert it directly
                # or save it in the decrypted stage.
                if self._queue_for_decrypt:
                    self._save_received_doc(doc, gen, trans_id, idx, total)
                else:
                    self._return_doc_cb(doc, gen, trans_id)
            # -------------------------------------------------------------
            # end of symmetric decryption
            # -------------------------------------------------------------
        msg = "%d/%d" % (idx + 1, total)
        signal(SOLEDAD_SYNC_RECEIVE_STATUS, msg)
        logger.debug("Soledad sync receive status: %s" % msg)
        return number_of_changes, new_generation, new_transaction_id

    def _get_remote_docs(self, url, last_known_generation, last_known_trans_id,
                         headers, return_doc_cb, ensure_callback, sync_id,
                         syncer_pool, defer_decryption=False):
        """
        Fetch sync documents from the remote database and insert them in the
        local database.

        If an incoming document's encryption scheme is equal to
        EncryptionSchemes.SYMKEY, then this method will decrypt it with
        Soledad's symmetric key.

        :param url: The syncing URL.
        :type url: str
        :param last_known_generation: Target's last known generation.
        :type last_known_generation: int
        :param last_known_trans_id: Target's last known transaction id.
        :type last_known_trans_id: str
        :param headers: The headers of the HTTP request.
        :type headers: dict
        :param return_doc_cb: A callback to insert docs from target.
        :type return_doc_cb: callable
        :param ensure_callback: A callback to ensure we have the correct
                                target_replica_uid, if it was just created.
        :type ensure_callback: callable
        :param sync_id: The id for the current sync session.
        :type sync_id: str
        :param defer_decryption: Whether to defer the decryption process using
                                 the intermediate database. If False,
                                 decryption will be done inline.
        :type defer_decryption: bool

        :raise BrokenSyncStream: If `data` is malformed.

        :return: A dictionary representing the first line of the response got
                 from remote replica.
        :rtype: dict
        """
        # we keep a reference to the callback in case we defer the decryption
        self._return_doc_cb = return_doc_cb
        self._queue_for_decrypt = defer_decryption \
            and self._sync_db is not None

        new_generation = last_known_generation
        new_transaction_id = last_known_trans_id

        if self._queue_for_decrypt:
            logger.debug(
                "Soledad sync: will queue received docs for decrypting.")

        idx = 0
        number_of_changes = 1

        first_request = True
        last_callback_lock = None
        threads = []

        # get incoming documents
        while idx < number_of_changes:
            # bail out if sync process was interrupted
            if self.stopped is True:
                break

            # launch a thread to fetch one document from target
            t = syncer_pool.new_syncer_thread(
                idx, number_of_changes,
                last_callback_lock=last_callback_lock)

            # bail out if any thread failed
            if t is None:
                self.stop()
                break

            t.doc_syncer.set_request_method(
                'get', idx, sync_id, last_known_generation,
                last_known_trans_id)
            t.doc_syncer.set_success_callback(self._insert_received_doc)

            def _failure_callback(idx, total, exception):
                _failure_msg = "Soledad sync: error while getting document " \
                    "%d/%d: %s" \
                    % (idx + 1, total, exception)
                logger.warning("%s" % _failure_msg)
                logger.warning("Soledad sync: failing gracefully, will "
                               "recover on next sync.")

            t.doc_syncer.set_failure_callback(_failure_callback)
            threads.append(t)
            t.start()
            last_callback_lock = t.callback_lock
            idx += 1

            # if this is the first request, wait to update the number of
            # changes
            if first_request is True:
                t.join()
                if t.success:
                    number_of_changes, _, _ = t.result
                first_request = False

        # make sure all threads finished and we have up-to-date info
        last_successful_thread = None
        while threads:
            # check if there are failures
            t = threads.pop(0)
            t.join()
            if t.success:
                last_successful_thread = t

        # get information about last successful thread
        if last_successful_thread is not None:
            body, _ = last_successful_thread.response
            parsed_body = json.loads(body)
            # get current target gen and trans id in case no documents were
            # transferred
            if len(parsed_body) == 1:
                metadata = parsed_body[0]
                new_generation = metadata['new_generation']
                new_transaction_id = metadata['new_transaction_id']
            # get current target gen and trans id from last transferred
            # document
            else:
                doc_data = parsed_body[1]
                new_generation = doc_data['gen']
                new_transaction_id = doc_data['trans_id']

        return new_generation, new_transaction_id

    def sync_exchange(self, docs_by_generations,
                      source_replica_uid, last_known_generation,
                      last_known_trans_id, return_doc_cb,
                      ensure_callback=None, defer_decryption=True,
                      sync_id=None):
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

        :param defer_decryption: Whether to defer the decryption process using
                                 the intermediate database. If False,
                                 decryption will be done inline.
        :type defer_decryption: bool

        :return: The new generation and transaction id of the target replica.
        :rtype: tuple
        """
        self._ensure_callback = ensure_callback

        if defer_decryption:
            self._sync_exchange_lock.acquire()
            self._setup_sync_decr_pool(last_known_generation)
            self._setup_sync_watcher()
            self._defer_decryption = True

        self.start()

        if sync_id is None:
            sync_id = str(uuid4())
        self.source_replica_uid = source_replica_uid
        # let the decrypter pool access the passed callback to insert docs
        setProxiedObject(self._insert_doc_cb[source_replica_uid],
                         return_doc_cb)

        if not self.clear_to_sync():
            raise PendingReceivedDocsSyncError

        self._ensure_connection()
        if self._trace_hook:  # for tests
            self._trace_hook('sync_exchange')
        url = '%s/sync-from/%s' % (self._url.path, source_replica_uid)
        headers = self._sign_request('POST', url, {})

        cur_target_gen = last_known_generation
        cur_target_trans_id = last_known_trans_id

        # send docs
        msg = "%d/%d" % (0, len(docs_by_generations))
        signal(SOLEDAD_SYNC_SEND_STATUS, msg)
        logger.debug("Soledad sync send status: %s" % msg)

        defer_encryption = self._sync_db is not None
        syncer_pool = DocumentSyncerPool(
            self._raw_url, self._raw_creds, url, headers, ensure_callback,
            self.stop)
        threads = []
        last_request_lock = None
        last_callback_lock = None
        sent = 0
        total = len(docs_by_generations)

        synced = []
        number_of_docs = len(docs_by_generations)

        for doc, gen, trans_id in docs_by_generations:
            # allow for interrupting the sync process
            if self.stopped is True:
                break

            # skip non-syncable docs
            if isinstance(doc, SoledadDocument) and not doc.syncable:
                continue

            # -------------------------------------------------------------
            # symmetric encryption of document's contents
            # -------------------------------------------------------------
            doc_json = doc.get_json()
            if not doc.is_tombstone():
                if not defer_encryption:
                    # fallback case, for tests
                    doc_json = encrypt_doc(self._crypto, doc)
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
                        # from the sync db. As it is not encrypted yet, we
                        # force inline encryption.
                        # TODO: implement a queue to deal with these cases.
                        doc_json = encrypt_doc(self._crypto, doc)
            # -------------------------------------------------------------
            # end of symmetric encryption
            # -------------------------------------------------------------
            t = syncer_pool.new_syncer_thread(
                sent + 1, total, last_request_lock=None,
                last_callback_lock=last_callback_lock)

            # bail out if any thread failed
            if t is None:
                self.stop()
                break

            # set the request method
            t.doc_syncer.set_request_method(
                'put', sync_id, cur_target_gen, cur_target_trans_id,
                id=doc.doc_id, rev=doc.rev, content=doc_json, gen=gen,
                trans_id=trans_id, number_of_docs=number_of_docs, doc_idx=sent + 1)
            # set the success calback

            def _success_callback(idx, total, response):
                _success_msg = "Soledad sync send status: %d/%d" \
                               % (idx, total)
                signal(SOLEDAD_SYNC_SEND_STATUS, _success_msg)
                logger.debug(_success_msg)

            t.doc_syncer.set_success_callback(_success_callback)

            # set the failure callback
            def _failure_callback(idx, total, exception):
                _failure_msg = "Soledad sync: error while sending document " \
                               "%d/%d: %s" % (idx, total, exception)
                logger.warning("%s" % _failure_msg)
                logger.warning("Soledad sync: failing gracefully, will "
                               "recover on next sync.")

            t.doc_syncer.set_failure_callback(_failure_callback)

            # save thread and append
            t.start()
            threads.append((t, doc))
            last_request_lock = t.request_lock
            last_callback_lock = t.callback_lock
            sent += 1

        # make sure all threads finished and we have up-to-date info
        last_successful_thread = None
        while threads:
            # check if there are failures
            t, doc = threads.pop(0)
            t.join()
            if t.success:
                synced.append((doc.doc_id, doc.rev))
                last_successful_thread = t

        # delete documents from the sync database
        if defer_encryption:
            self.delete_encrypted_docs_from_db(synced)

        # get target gen and trans_id after docs
        gen_after_send = None
        trans_id_after_send = None
        if last_successful_thread is not None:
            response_dict = json.loads(last_successful_thread.response[0])[0]
            gen_after_send = response_dict['new_generation']
            trans_id_after_send  = response_dict['new_transaction_id']

        # get docs from target
        if self.stopped is False:
            cur_target_gen, cur_target_trans_id = self._get_remote_docs(
                url,
                last_known_generation, last_known_trans_id, headers,
                return_doc_cb, ensure_callback, sync_id, syncer_pool,
                defer_decryption=defer_decryption)

        syncer_pool.cleanup()

        # decrypt docs in case of deferred decryption
        if defer_decryption:
            self._sync_watcher.start()
            while self.clear_to_sync() is False:
                sleep(self.DECRYPT_TASK_PERIOD)
            self._teardown_sync_watcher()
            self._teardown_sync_decr_pool()
            self._sync_exchange_lock.release()

        # update gen and trans id info in case we just sent and did not
        # receive docs.
        if gen_after_send is not None and gen_after_send > cur_target_gen:
            cur_target_gen = gen_after_send
            cur_target_trans_id = trans_id_after_send

        self.stop()
        return cur_target_gen, cur_target_trans_id

    def start(self):
        """
        Mark current sync session as running.
        """
        with self._stop_lock:
            self._stopped = False

    def stop(self):
        """
        Mark current sync session as stopped.

        This will eventually interrupt the sync_exchange() method and return
        enough information to the synchronizer so the sync session can be
        recovered afterwards.
        """
        with self._stop_lock:
            self._stopped = True

    @property
    def stopped(self):
        """
        Return whether this sync session is stopped.

        :return: Whether this sync session is stopped.
        :rtype: bool
        """
        with self._stop_lock:
            return self._stopped is True

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
        if docs_ids:
            encr = SyncEncrypterPool
            c = self._sync_db.cursor()
            for doc_id, doc_rev in docs_ids:
                sql = ("DELETE FROM %s WHERE doc_id=? and rev=?" % (
                    encr.TABLE_NAME,))
                c.execute(sql, (doc_id, doc_rev))
            self._sync_db.commit()

    def _save_encrypted_received_doc(self, doc, gen, trans_id, idx, total):
        """
        Save a symmetrically encrypted incoming document into the received
        docs table in the sync db. A decryption task will pick it up
        from here in turn.

        :param doc: The document to save.
        :type doc: SoledadDocument
        :param gen: The generation.
        :type gen: str
        :param  trans_id: Transacion id.
        :type gen: str
        :param idx: The index count of the current operation.
        :type idx: int
        :param total: The total number of operations.
        :type total: int
        """
        logger.debug(
            "Enqueueing doc for decryption: %d/%d."
            % (idx + 1, total))
        self._sync_decr_pool.insert_encrypted_received_doc(
            doc.doc_id, doc.rev, doc.content, gen, trans_id)

    def _save_received_doc(self, doc, gen, trans_id, idx, total):
        """
        Save any incoming document into the received docs table in the sync db.

        :param doc: The document to save.
        :type doc: SoledadDocument
        :param gen: The generation.
        :type gen: str
        :param  trans_id: Transacion id.
        :type gen: str
        :param idx: The index count of the current operation.
        :type idx: int
        :param total: The total number of operations.
        :type total: int
        """
        logger.debug(
            "Enqueueing doc, no decryption needed: %d/%d."
            % (idx + 1, total))
        self._sync_decr_pool.insert_received_doc(
            doc.doc_id, doc.rev, doc.content, gen, trans_id)

    #
    # Symmetric decryption of syncing docs
    #

    def clear_to_sync(self):
        """
        Return True if sync can proceed (ie, the received db table is empty).
        :rtype: bool
        """
        if self._sync_decr_pool is not None:
            return self._sync_decr_pool.count_docs_in_sync_db() == 0
        else:
            return True

    def set_decryption_callback(self, cb):
        """
        Set callback to be called when the decryption finishes.

        :param cb: The callback to be set.
        :type cb: callable
        """
        self._decryption_callback = cb

    def has_decryption_callback(self):
        """
        Return True if there is a decryption callback set.
        :rtype: bool
        """
        return self._decryption_callback is not None

    def has_syncdb(self):
        """
        Return True if we have an initialized syncdb.
        """
        return self._sync_db is not None

    def _decrypt_syncing_received_docs(self):
        """
        Decrypt the documents received from remote replica and insert them
        into the local one.

        Called periodically from TimerTask self._sync_watcher.
        """
        if sameProxiedObjects(
                self._insert_doc_cb.get(self.source_replica_uid),
                None):
            return

        decrypter = self._sync_decr_pool
        decrypter.decrypt_received_docs()
        done = decrypter.process_decrypted()

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

    def set_token_credentials(self, uuid, token):
        """
        Store given credentials so we can sign the request later.

        :param uuid: The user's uuid.
        :type uuid: str
        :param token: The authentication token.
        :type token: str
        """
        TokenBasedAuth.set_token_credentials(self, uuid, token)
