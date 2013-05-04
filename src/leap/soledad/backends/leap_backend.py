# -*- coding: utf-8 -*-
# leap_backend.py
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

try:
    import simplejson as json
except ImportError:
    import json  # noqa


from u1db import Document
from u1db.remote import utils
from u1db.errors import BrokenSyncStream
from u1db.remote.http_target import HTTPSyncTarget


from leap.common.keymanager import KeyManager
from leap.common.check import leap_assert
from leap.soledad.auth import TokenBasedAuth

#
# Exceptions
#

class DocumentNotEncrypted(Exception):
    """
    Raised for failures in document encryption.
    """
    pass


class UnknownEncryptionSchemes(Exception):
    """
    Raised when trying to decrypt from unknown encryption schemes.
    """


#
# Encryption schemes used for encryption.
#

class EncryptionSchemes(object):
    """
    Representation of encryption schemes used to encrypt documents.
    """

    NONE = 'none'
    SYMKEY = 'symkey'
    PUBKEY = 'pubkey'


#
# Crypto utilities for a LeapDocument.
#

ENC_JSON_KEY = '_enc_json'
ENC_SCHEME_KEY = '_enc_scheme'
MAC_KEY = '_mac'


def encrypt_doc_json(crypto, doc_id, doc_json):
    """
    Return a valid JSON string containing the C{doc} content encrypted to
    a symmetric key and the encryption scheme.

    The returned JSON string is the serialization of the following dictionary:

        {
            '_enc_json': encrypt_sym(doc_content),
            '_enc_scheme': 'symkey',
            '_mac': <mac> [Not implemented yet]
        }

    @param crypto: A SoledadCryto instance to perform the encryption.
    @type crypto: leap.soledad.crypto.SoledadCrypto
    @param doc_id: The unique id of the document.
    @type doc_id: str
    @param doc_json: The JSON serialization of the document's contents.
    @type doc_json: str

    @return: The JSON serialization representing the encrypted content.
    @rtype: str
    """
    ciphertext = crypto.encrypt_sym(
        doc_json,
        crypto.passphrase_hash(doc_id))
    if not crypto.is_encrypted_sym(ciphertext):
        raise DocumentNotEncrypted('Failed encrypting document.')
    return json.dumps({
        ENC_JSON_KEY: ciphertext,
        ENC_SCHEME_KEY: EncryptionSchemes.SYMKEY,
    })


def decrypt_doc_json(crypto, doc_id, doc_json):
    """
    Return a JSON serialization of the decrypted content contained in
    C{encrypted_json}.

    The C{encrypted_json} parameter is the JSON serialization of the
    following dictionary:

        {
            ENC_JSON_KEY: enc_blob,
            ENC_SCHEME_KEY: enc_scheme,
        }

    C{enc_blob} is the encryption of the JSON serialization of the document's
    content. For now Soledad just deals with documents whose C{enc_scheme} is
    EncryptionSchemes.SYMKEY.

    @param crypto: A SoledadCryto instance to perform the encryption.
    @type crypto: leap.soledad.crypto.SoledadCrypto
    @param doc_id: The unique id of the document.
    @type doc_id: str
    @param doc_json: The JSON serialization representation of the encrypted
        document's contents.
    @type doc_json: str

    @return: The JSON serialization of the decrypted content.
    @rtype: str
    """
    leap_assert(isinstance(doc_id, str), 'Document id is not a string.')
    leap_assert(doc_id != '', 'Received empty document id.')
    leap_assert(isinstance(doc_json, str), 'Document JSON is not a string.')
    leap_assert(doc_json != '', 'Received empty document JSON.')
    content = json.loads(doc_json)
    ciphertext = content[ENC_JSON_KEY]
    enc_scheme = content[ENC_SCHEME_KEY]
    plainjson = None
    if enc_scheme == EncryptionSchemes.SYMKEY:
        if not crypto.is_encrypted_sym(ciphertext):
            raise DocumentNotEncrypted(
                'Unable to identify document encryption for incoming '
                'document, although it is marked as being encrypted with a '
                'symmetric key.')
        plainjson = crypto.decrypt_sym(
            ciphertext,
            crypto.passphrase_hash(doc_id))
    else:
        raise UnknownEncryptionSchemes(enc_scheme)
    return plainjson


class LeapDocument(Document):
    """
    Encryptable and syncable document.

    LEAP Documents can be flagged as syncable or not, so the replicas
    might not sync every document.
    """

    def __init__(self, doc_id=None, rev=None, json='{}', has_conflicts=False,
                 syncable=True):
        """
        Container for handling an encryptable document.

        @param doc_id: The unique document identifier.
        @type doc_id: str
        @param rev: The revision identifier of the document.
        @type rev: str
        @param json: The JSON string for this document.
        @type json: str
        @param has_conflicts: Boolean indicating if this document has conflicts
        @type has_conflicts: bool
        @param syncable: Should this document be synced with remote replicas?
        @type syncable: bool
        """
        Document.__init__(self, doc_id, rev, json, has_conflicts)
        self._syncable = syncable

    def _get_syncable(self):
        """
        Return whether this document is syncable.

        @return: Is this document syncable?
        @rtype: bool
        """
        return self._syncable

    def _set_syncable(self, syncable=True):
        """
        Determine if this document should be synced with remote replicas.

        @param syncable: Should this document be synced with remote replicas?
        @type syncable: bool
        """
        self._syncable = syncable

    syncable = property(
        _get_syncable,
        _set_syncable,
        doc="Determine if document should be synced with server."
    )

    def _get_rev(self):
        """
        Get the document revision.

        Returning the revision as string solves the following exception in
        Twisted web:
            exceptions.TypeError: Can only pass-through bytes on Python 2

        @return: The document revision.
        @rtype: str
        """
        if self._rev is None:
            return None
        return str(self._rev)

    def _set_rev(self, rev):
        """
        Set document revision.

        @param rev: The new document revision.
        @type rev: bytes
        """
        self._rev = rev

    rev = property(
        _get_rev,
        _set_rev,
        doc="Wrapper to ensure `doc.rev` is always returned as bytes.")


#
# LeapSyncTarget
#

class LeapSyncTarget(HTTPSyncTarget, TokenBasedAuth):
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

        @param uuid: The user's uuid.
        @type uuid: str
        @param token: The authentication token.
        @type token: str
        """
        TokenBasedAuth.set_token_credentials(self, uuid, token)

    def _sign_request(self, method, url_query, params):
        """
        Return an authorization header to be included in the HTTP request.

        @param method: The HTTP method.
        @type method: str
        @param url_query: The URL query string.
        @type url_query: str
        @param params: A list with encoded query parameters.
        @type param: list

        @return: The Authorization header.
        @rtype: list of tuple
        """
        return TokenBasedAuth._sign_request(self, method, url_query, params)

    #
    # Modified HTTPSyncTarget methods.
    #

    @staticmethod
    def connect(url, crypto=None):
        return LeapSyncTarget(url, crypto=crypto)

    def __init__(self, url, creds=None, crypto=None):
        """
        Initialize the LeapSyncTarget.

        @param url: The url of the target replica to sync with.
        @type url: str
        @param creds: optional dictionary giving credentials.
            to authorize the operation with the server.
        @type creds: dict
        @param soledad: An instance of Soledad so we can encrypt/decrypt
            document contents when syncing.
        @type soledad: soledad.Soledad
        """
        HTTPSyncTarget.__init__(self, url, creds)
        self._crypto = crypto

    def _parse_sync_stream(self, data, return_doc_cb, ensure_callback=None):
        """
        Parse incoming synchronization stream and insert documents in the
        local database.

        If an incoming document's encryption scheme is equal to
        EncryptionSchemes.SYMKEY, then this method will decrypt it with
        Soledad's symmetric key.

        @param data: The body of the HTTP response.
        @type data: str
        @param return_doc_cb: A callback to insert docs from target.
        @type return_doc_cb: function
        @param ensure_callback: A callback to ensure we have the correct
            target_replica_uid, if it was just created.
        @type ensure_callback: function

        @raise BrokenSyncStream: If C{data} is malformed.

        @return: A dictionary representing the first line of the response got
            from remote replica.
        @rtype: list of str
        """
        parts = data.splitlines()  # one at a time
        if not parts or parts[0] != '[':
            raise BrokenSyncStream
        data = parts[1:-1]
        comma = False
        if data:
            line, comma = utils.check_and_strip_comma(data[0])
            res = json.loads(line)
            if ensure_callback and 'replica_uid' in res:
                ensure_callback(res['replica_uid'])
            for entry in data[1:]:
                if not comma:  # missing in between comma
                    raise BrokenSyncStream
                line, comma = utils.check_and_strip_comma(entry)
                entry = json.loads(line)
                #-------------------------------------------------------------
                # symmetric decryption of document's contents
                #-------------------------------------------------------------
                # if arriving content was symmetrically encrypted, we decrypt
                # it.
                doc = LeapDocument(entry['id'], entry['rev'], entry['content'])
                if doc.content and ENC_SCHEME_KEY in doc.content:
                    if doc.content[ENC_SCHEME_KEY] == \
                            EncryptionSchemes.SYMKEY:
                        doc.set_json(
                            decrypt_doc_json(
                                self._crypto, doc.doc_id, entry['content']))
                #-------------------------------------------------------------
                # end of symmetric decryption
                #-------------------------------------------------------------
                return_doc_cb(doc, entry['gen'], entry['trans_id'])
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

    def sync_exchange(self, docs_by_generations, source_replica_uid,
                      last_known_generation, last_known_trans_id,
                      return_doc_cb, ensure_callback=None):
        """
        Find out which documents the remote database does not know about,
        encrypt and send them.

        This does the same as the parent's method but encrypts content before
        syncing.

        @param docs_by_generations: A list of (doc_id, generation, trans_id)
            of local documents that were changed since the last local
            generation the remote replica knows about.
        @type docs_by_generations: list of tuples
        @param source_replica_uid: The uid of the source replica.
        @type source_replica_uid: str
        @param last_known_generation: Target's last known generation.
        @type last_known_generation: int
        @param last_known_trans_id: Target's last known transaction id.
        @type last_known_trans_id: str
        @param return_doc_cb: A callback for inserting received documents from
            target.
        @type return_doc_cb: function
        @param ensure_callback: A callback that ensures we know the target
            replica uid if the target replica was just created.
        @type ensure_callback: function

        @return: The new generation and transaction id of the target replica.
        @rtype: tuple
        """
        self._ensure_connection()
        if self._trace_hook:  # for tests
            self._trace_hook('sync_exchange')
        url = '%s/sync-from/%s' % (self._url.path, source_replica_uid)
        self._conn.putrequest('POST', url)
        self._conn.putheader('content-type', 'application/x-u1db-sync-stream')
        for header_name, header_value in self._sign_request('POST', url, {}):
            self._conn.putheader(header_name, header_value)
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
        for doc, gen, trans_id in docs_by_generations:
            # skip non-syncable docs
            if isinstance(doc, LeapDocument) and not doc.syncable:
                continue
            #-------------------------------------------------------------
            # symmetric encryption of document's contents
            #-------------------------------------------------------------
            enc_json = doc.get_json()
            if not doc.is_tombstone():
                enc_json = encrypt_doc_json(
                    self._crypto, doc.doc_id, doc.get_json())
            #-------------------------------------------------------------
            # end of symmetric encryption
            #-------------------------------------------------------------
            size += prepare(id=doc.doc_id, rev=doc.rev,
                            content=enc_json,
                            gen=gen, trans_id=trans_id)
        entries.append('\r\n]')
        size += len(entries[-1])
        self._conn.putheader('content-length', str(size))
        self._conn.endheaders()
        for entry in entries:
            self._conn.send(entry)
        entries = None
        data, _ = self._response()
        res = self._parse_sync_stream(data, return_doc_cb, ensure_callback)
        data = None
        return res['new_generation'], res['new_transaction_id']
