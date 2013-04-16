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

import uuid
try:
    import simplejson as json
except ImportError:
    import json  # noqa


from u1db import Document
from u1db.remote import utils
from u1db.remote.http_target import HTTPSyncTarget
from u1db.remote.http_database import HTTPDatabase
from u1db.errors import BrokenSyncStream


class NoDefaultKey(Exception):
    """
    Exception to signal that there's no default OpenPGP key configured.
    """
    pass


class NoSoledadInstance(Exception):
    """
    Exception to signal that no Soledad instance was found.
    """
    pass


class DocumentNotEncrypted(Exception):
    """
    Raised for failures in document encryption.
    """
    pass


class LeapDocument(Document):
    """
    Encryptable and syncable document.

    LEAP Documents are standard u1db documents with cabability of returning an
    encrypted version of the document json string as well as setting document
    content based on an encrypted version of json string.

    Also, LEAP Documents can be flagged as syncable or not, so the replicas
    might not sync every document.
    """

    def __init__(self, doc_id=None, rev=None, json='{}', has_conflicts=False,
                 encrypted_json=None, soledad=None, syncable=True):
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
        @param encrypted_json: The encrypted JSON string for this document. If
            given, the decrypted value supersedes any raw json string given.
        @type encrypted_json: str
        @param soledad: An instance of Soledad so we can encrypt/decrypt
            document contents when syncing.
        @type soledad: soledad.Soledad
        @param syncable: Should this document be synced with remote replicas?
        @type syncable: bool
        """
        Document.__init__(self, doc_id, rev, json, has_conflicts)
        self._soledad = soledad
        self._syncable = syncable
        if encrypted_json:
            self.set_encrypted_json(encrypted_json)

    def get_encrypted_content(self):
        """
        Return an encrypted JSON serialization of document's contents.

        @return: The encrypted JSON serialization of document's contents.
        @rtype: str
        """
        if not self._soledad:
            raise NoSoledadInstance()
        return self._soledad.encrypt_symmetric(self.doc_id,
                                               self.get_json())

    def set_encrypted_content(self, cyphertext):
        """
        Decrypt C{cyphertext} and set document's content.
        contents.
        """
        plaintext = self._soledad.decrypt_symmetric(self.doc_id, cyphertext)
        self.set_json(plaintext)

    def get_encrypted_json(self):
        """
        Return a valid JSON string containing document's content encrypted to
        the user's public key.

        @return: The encrypted JSON string.
        @rtype: str
        """
        return json.dumps({'_encrypted_json': self.get_encrypted_content()})

    def set_encrypted_json(self, encrypted_json):
        """
        Set document's content based on a valid JSON string containing the
        encrypted document's contents.
        """
        if not self._soledad:
            raise NoSoledadInstance()
        cyphertext = json.loads(encrypted_json)['_encrypted_json']
        self.set_encrypted_content(cyphertext)

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


class LeapSyncTarget(HTTPSyncTarget):
    """
    A SyncTarget that encrypts data before sending and decrypts data after
    receiving.
    """

    def __init__(self, url, creds=None, soledad=None):
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
        self._soledad = soledad

    def _parse_sync_stream(self, data, return_doc_cb, ensure_callback=None):
        """
        Does the same as parent's method but ensures incoming content will be
        decrypted.

        @param data: The body of the HTTP response.
        @type data: str
        @param return_doc_cb: A callback to insert docs from target.
        @type return_doc_cb: function
        @param ensure_callback: A callback to ensure we have the correct
            target_replica_uid, if it was just created.
        @type ensure_callback: function

        @return: The parsed sync stream.
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
                # decrypt after receiving from server.
                if not self._soledad:
                    raise NoSoledadInstance()
                enc_json = json.loads(entry['content'])['_encrypted_json']
                if not self._soledad.is_encrypted_sym(enc_json):
                    raise DocumentNotEncrypted(
                        "Incoming document from sync is not encrypted.")
                doc = LeapDocument(entry['id'], entry['rev'],
                                   encrypted_json=entry['content'],
                                   soledad=self._soledad)
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
        Does the same as parent's method but encrypts content before syncing.
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
            if doc.syncable:
                # encrypt and verify before sending to server.
                enc_json = json.loads(
                    doc.get_encrypted_json())['_encrypted_json']
                if not self._soledad.is_encrypted_sym(enc_json):
                    raise DocumentNotEncrypted(
                        "Could not encrypt document before sync.")
                size += prepare(id=doc.doc_id, rev=doc.rev,
                                content=doc.get_encrypted_json(),
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
