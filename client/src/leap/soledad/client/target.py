# -*- coding: utf-8 -*-
# target.py
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
A U1DB backend for encrypting data before sending to server and decrypting
after receiving.
"""
import binascii
import cStringIO
import gzip
import hashlib
import hmac
import logging
import urllib

import simplejson as json
from time import sleep
from uuid import uuid4

from u1db.remote import utils, http_errors
from u1db.errors import BrokenSyncStream
from u1db import errors
from u1db.remote.http_target import HTTPSyncTarget
from u1db.remote.http_client import _encode_query_parameter


from leap.soledad.common import soledad_assert
from leap.soledad.common.crypto import (
    EncryptionSchemes,
    UnknownEncryptionScheme,
    MacMethods,
    UnknownMacMethod,
    WrongMac,
    ENC_JSON_KEY,
    ENC_SCHEME_KEY,
    ENC_METHOD_KEY,
    ENC_IV_KEY,
    MAC_KEY,
    MAC_METHOD_KEY,
)
from leap.soledad.common.document import SoledadDocument
from leap.soledad.client.auth import TokenBasedAuth
from leap.soledad.client.crypto import (
    EncryptionMethods,
    UnknownEncryptionMethod,
)

logger = logging.getLogger(__name__)

#
# Exceptions
#


class DocumentNotEncrypted(Exception):
    """
    Raised for failures in document encryption.
    """
    pass


#
# Crypto utilities for a SoledadDocument.
#


def mac_doc(crypto, doc_id, doc_rev, ciphertext, mac_method):
    """
    Calculate a MAC for C{doc} using C{ciphertext}.

    Current MAC method used is HMAC, with the following parameters:

        * key: sha256(storage_secret, doc_id)
        * msg: doc_id + doc_rev + ciphertext
        * digestmod: sha256

    :param crypto: A SoledadCryto instance used to perform the encryption.
    :type crypto: leap.soledad.crypto.SoledadCrypto
    :param doc_id: The id of the document.
    :type doc_id: str
    :param doc_rev: The revision of the document.
    :type doc_rev: str
    :param ciphertext: The content of the document.
    :type ciphertext: str
    :param mac_method: The MAC method to use.
    :type mac_method: str

    :return: The calculated MAC.
    :rtype: str
    """
    if mac_method == MacMethods.HMAC:
        return hmac.new(
            crypto.doc_mac_key(doc_id),
            str(doc_id) + str(doc_rev) + ciphertext,
            hashlib.sha256).digest()
    # raise if we do not know how to handle this MAC method
    raise UnknownMacMethod('Unknown MAC method: %s.' % mac_method)


def encrypt_doc(crypto, doc):
    """
    Encrypt C{doc}'s content.

    Encrypt doc's contents using AES-256 CTR mode and return a valid JSON
    string representing the following:

        {
            ENC_JSON_KEY: '<encrypted doc JSON string>',
            ENC_SCHEME_KEY: 'symkey',
            ENC_METHOD_KEY: EncryptionMethods.AES_256_CTR,
            ENC_IV_KEY: '<the initial value used to encrypt>',
            MAC_KEY: '<mac>'
            MAC_METHOD_KEY: 'hmac'
        }

    :param crypto: A SoledadCryto instance used to perform the encryption.
    :type crypto: leap.soledad.crypto.SoledadCrypto
    :param doc: The document with contents to be encrypted.
    :type doc: SoledadDocument

    :return: The JSON serialization of the dict representing the encrypted
        content.
    :rtype: str
    """
    soledad_assert(doc.is_tombstone() is False)
    # encrypt content using AES-256 CTR mode
    iv, ciphertext = crypto.encrypt_sym(
        str(doc.get_json()),  # encryption/decryption routines expect str
        crypto.doc_passphrase(doc.doc_id),
        method=EncryptionMethods.AES_256_CTR)
    # Return a representation for the encrypted content. In the following, we
    # convert binary data to hexadecimal representation so the JSON
    # serialization does not complain about what it tries to serialize.
    hex_ciphertext = binascii.b2a_hex(ciphertext)
    return json.dumps({
        ENC_JSON_KEY: hex_ciphertext,
        ENC_SCHEME_KEY: EncryptionSchemes.SYMKEY,
        ENC_METHOD_KEY: EncryptionMethods.AES_256_CTR,
        ENC_IV_KEY: iv,
        # store the mac as hex.
        MAC_KEY: binascii.b2a_hex(
            mac_doc(
                crypto, doc.doc_id, doc.rev,
                ciphertext,
                MacMethods.HMAC)),
        MAC_METHOD_KEY: MacMethods.HMAC,
    })


def decrypt_doc(crypto, doc):
    """
    Decrypt C{doc}'s content.

    Return the JSON string representation of the document's decrypted content.

    The content of the document should have the following structure:

        {
            ENC_JSON_KEY: '<enc_blob>',
            ENC_SCHEME_KEY: '<enc_scheme>',
            ENC_METHOD_KEY: '<enc_method>',
            ENC_IV_KEY: '<initial value used to encrypt>',  # (optional)
            MAC_KEY: '<mac>'
            MAC_METHOD_KEY: 'hmac'
        }

    C{enc_blob} is the encryption of the JSON serialization of the document's
    content. For now Soledad just deals with documents whose C{enc_scheme} is
    EncryptionSchemes.SYMKEY and C{enc_method} is
    EncryptionMethods.AES_256_CTR.

    :param crypto: A SoledadCryto instance to perform the encryption.
    :type crypto: leap.soledad.crypto.SoledadCrypto
    :param doc: The document to be decrypted.
    :type doc: SoledadDocument

    :return: The JSON serialization of the decrypted content.
    :rtype: str
    """
    soledad_assert(doc.is_tombstone() is False)
    soledad_assert(ENC_JSON_KEY in doc.content)
    soledad_assert(ENC_SCHEME_KEY in doc.content)
    soledad_assert(ENC_METHOD_KEY in doc.content)
    soledad_assert(MAC_KEY in doc.content)
    soledad_assert(MAC_METHOD_KEY in doc.content)
    # verify MAC
    ciphertext = binascii.a2b_hex(  # content is stored as hex.
        doc.content[ENC_JSON_KEY])
    mac = mac_doc(
        crypto, doc.doc_id, doc.rev,
        ciphertext,
        doc.content[MAC_METHOD_KEY])
    # we compare mac's hashes to avoid possible timing attacks that might
    # exploit python's builtin comparison operator behaviour, which fails
    # immediatelly when non-matching bytes are found.
    doc_mac_hash = hashlib.sha256(
        binascii.a2b_hex(  # the mac is stored as hex
            doc.content[MAC_KEY])).digest()
    calculated_mac_hash = hashlib.sha256(mac).digest()
    if doc_mac_hash != calculated_mac_hash:
        raise WrongMac('Could not authenticate document\'s contents.')
    # decrypt doc's content
    enc_scheme = doc.content[ENC_SCHEME_KEY]
    plainjson = None
    if enc_scheme == EncryptionSchemes.SYMKEY:
        enc_method = doc.content[ENC_METHOD_KEY]
        if enc_method == EncryptionMethods.AES_256_CTR:
            soledad_assert(ENC_IV_KEY in doc.content)
            plainjson = crypto.decrypt_sym(
                ciphertext,
                crypto.doc_passphrase(doc.doc_id),
                method=enc_method,
                iv=doc.content[ENC_IV_KEY])
        else:
            raise UnknownEncryptionMethod(enc_method)
    else:
        raise UnknownEncryptionScheme(enc_scheme)
    return plainjson


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


#
# SoledadSyncTarget
#

class SoledadSyncTarget(HTTPSyncTarget, TokenBasedAuth):
    """
    A SyncTarget that encrypts data before sending and decrypts data after
    receiving.
    """

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
    # Modified HTTPSyncTarget methods.
    #

    @staticmethod
    def connect(url, crypto=None):
        return SoledadSyncTarget(url, crypto=crypto)

    def __init__(self, url, creds=None, crypto=None):
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
        """
        HTTPSyncTarget.__init__(self, url, creds)
        self._crypto = crypto

    def _init_post_request(self, url, action, headers, content_length):
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
        self._conn.putrequest('POST', url)
        self._conn.putheader(
            'content-type', 'application/x-soledad-sync-%s' % action)
        for header_name, header_value in headers:
            self._conn.putheader(header_name, header_value)
        self._conn.putheader('accept-encoding', 'gzip')
        self._conn.putheader('content-length', str(content_length))
        self._conn.endheaders()

    def _get_remote_docs(self, url, last_known_generation, last_known_trans_id,
                         headers, return_doc_cb, ensure_callback=None):
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

        :raise BrokenSyncStream: If C{data} is malformed.

        :return: A dictionary representing the first line of the response got
            from remote replica.
        :rtype: list of str
        """

        def _post_get_doc(received):
            """
            Get a sync document from server by means of a POST request.

            :param received: How many documents have already been received in
                             this sync session.
            :type received: int
            """
            entries = ['[']
            size = 1
            # add remote replica metadata to the request
            size += self._prepare(
                '', entries,
                last_known_generation=last_known_generation,
                last_known_trans_id=last_known_trans_id,
                ensure=ensure_callback is not None)
            # inform server of how many documents have already been received
            size += self._prepare(',', entries, received=received)
            entries.append('\r\n]')
            size += len(entries[-1])
            # send headers
            self._init_post_request(url, 'get', headers, size)
            # get document
            for entry in entries:
                self._conn.send(entry)
            return self._response()

        received = 0
        number_of_changes = None

        while number_of_changes is None or received < number_of_changes:
            # try to fetch one document from target
            data, _ = _post_get_doc(received)
            received += 1
            # decode incoming stream
            entries = None
            try:
                entries = json.loads(data)
            except ValueError:
                raise BrokenSyncStream
            # bail out if there are no documents to be received
            try:
                number_of_changes = entries[0]['number_of_changes']
            except IndexError, KeyError:
                raise BrokenSyncStream
            if number_of_changes == 0:
                break
            # decrypt incoming document and insert into local database
            entry = None
            try:
                entry = entries[1]
            except IndexError:
                raise BrokenSyncStream
            if ensure_callback and 'replica_uid' in res:
                ensure_callback(res['replica_uid'])
            # -------------------------------------------------------------
            # symmetric decryption of document's contents
            # -------------------------------------------------------------
            # if arriving content was symmetrically encrypted, we decrypt
            # it.
            doc = SoledadDocument(
                entry['id'], entry['rev'], entry['content'])
            if doc.content and ENC_SCHEME_KEY in doc.content:
                if doc.content[ENC_SCHEME_KEY] == \
                        EncryptionSchemes.SYMKEY:
                    doc.set_json(decrypt_doc(self._crypto, doc))
            # -------------------------------------------------------------
            # end of symmetric decryption
            # -------------------------------------------------------------
            return_doc_cb(doc, entry['gen'], entry['trans_id'])
        return entries[0]['new_generation'], entries[0]['new_transaction_id']

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
        """
        entry = comma + '\r\n' + json.dumps(dic)
        entries.append(entry)
        return len(entry)

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
            target.
        :type return_doc_cb: function
        :param ensure_callback: A callback that ensures we know the target
            replica uid if the target replica was just created.
        :type ensure_callback: function

        :return: The new generation and transaction id of the target replica.
        :rtype: tuple
        """
        self._ensure_connection()
        if self._trace_hook:  # for tests
            self._trace_hook('sync_exchange')
        url = '%s/sync-from/%s' % (self._url.path, source_replica_uid)
        headers = self._sign_request('POST', url, {})

        def _post_put_doc(headers, last_known_generation, last_known_trans_id,
                          id, rev, content, gen, trans_id):
            """
            Put a sync document on server by means of a POST request.

            :param received: How many documents have already been received in
                             this sync session.
            :type received: int
            """
            # prepare to send the document
            entries = ['[']
            size = 1
            # add remote replica metadata to the request
            size += self._prepare(
                '', entries,
                last_known_generation=last_known_generation,
                last_known_trans_id=last_known_trans_id,
                ensure=ensure_callback is not None)
            # add the document to the request
            size += self._prepare(
                ',', entries,
                id=id, rev=rev, content=content, gen=gen, trans_id=trans_id)
            entries.append('\r\n]')
            size += len(entries[-1])
            # send headers
            self._init_post_request(url, 'put', headers, size)
            # send document
            for entry in entries:
                self._conn.send(entry)
            data, _ = self._response()
            data = json.loads(data)
            return data[0]['new_generation'], data[0]['new_transaction_id']

        cur_target_gen = last_known_generation
        cur_target_trans_id = last_known_trans_id

        for doc, gen, trans_id in docs_by_generations:
            # skip non-syncable docs
            if isinstance(doc, SoledadDocument) and not doc.syncable:
                continue
            # -------------------------------------------------------------
            # symmetric encryption of document's contents
            # -------------------------------------------------------------
            doc_json = doc.get_json()
            if not doc.is_tombstone():
                doc_json = encrypt_doc(self._crypto, doc)
            # -------------------------------------------------------------
            # end of symmetric encryption
            # -------------------------------------------------------------
            cur_target_gen, cur_target_trans_id = _post_put_doc(
                headers, cur_target_gen, cur_target_trans_id, id=doc.doc_id,
                rev=doc.rev, content=doc_json, gen=gen, trans_id=trans_id)

        cur_target_gen, cur_target_trans_id = self._get_remote_docs(
            url,
            last_known_generation, last_known_trans_id, headers,
            return_doc_cb, ensure_callback)

        return cur_target_gen, cur_target_trans_id
