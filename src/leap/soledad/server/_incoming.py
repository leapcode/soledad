# -*- coding: utf-8 -*-
# _incoming.py
# Copyright (C) 2017 LEAP
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
A twisted resource that saves externally delivered documents into user's db.
"""
import base64

from io import BytesIO
from twisted.web.server import NOT_DONE_YET
from twisted.web.resource import Resource
from twisted.web.client import FileBodyProducer

from leap.soledad.common.blobs import Flags
from leap.soledad.common.blobs import preamble
from leap.soledad.common.couch.state import CouchServerState
from leap.soledad.common.crypto import ENC_JSON_KEY
from leap.soledad.common.crypto import ENC_SCHEME_KEY
from leap.soledad.common.crypto import EncryptionSchemes
from leap.soledad.common.document import ServerDocument
from leap.soledad.common.log import getLogger

from leap.soledad.server._config import get_config
from leap.soledad.server._blobs import BlobsServerState
from leap.soledad.server._blobs import BlobExists
from leap.soledad.server._blobs import QuotaExceeded


__all__ = ['IncomingResource']


logger = getLogger(__name__)


def _get_backend_from_config():
    conf = get_config()
    if conf['blobs']:
        return BlobsServerState("filesystem", blobs_path=conf['blobs_path'])
    return CouchServerState(conf['couch_url'])


def uses_legacy(db):
    return hasattr(db, 'put_doc')


class IncomingResource(Resource):
    isLeaf = True

    def __init__(self, backend_factory=None):
        self.factory = backend_factory or _get_backend_from_config()
        self.formatter = IncomingFormatter()

    def render_PUT(self, request):
        uuid, doc_id = request.postpath
        scheme = EncryptionSchemes.PUBKEY
        db = self.factory.open_database(uuid)
        if uses_legacy(db):
            self._put_legacy(doc_id, scheme, db, request)
        else:
            self._put_incoming(uuid, doc_id, scheme, db, request)
        return NOT_DONE_YET

    def _put_legacy(self, doc_id, scheme, db, request):
        try:
            doc = ServerDocument(doc_id)
            content = request.content.read()
            doc.content = self.formatter.format(content, scheme)
            db.put_doc(doc)
            self._finish(request)
        except Exception as e:
            self._error(e, request)

    def _put_incoming(self, user, blob_id, scheme, db, request):
        raw_content = request.content.read()
        preamble = self.formatter.preamble(raw_content, blob_id)
        request.content = BytesIO(preamble + ' ' + raw_content)

        def catchBlobExists(failure):
            failure.trap(BlobExists)
            request.setResponseCode(409)
            request.write("Blob already exists: %s" % blob_id)
            request.finish()

        def catchQuotaExceeded(failure):
            failure.trap(QuotaExceeded)
            logger.error("Error 507: Quota exceeded for user: %s" % user)
            request.setResponseCode(507)
            request.write('Quota Exceeded!')
            request.finish()

        producer = FileBodyProducer(request.content)
        d = db.write_blob(user, blob_id, producer, namespace='MX')
        flags = [Flags.PENDING]
        d.addCallback(lambda _: db.set_flags(user, blob_id, flags,
                                             namespace='MX'))
        d.addCallback(lambda _: request.finish())
        d.addErrback(catchBlobExists)
        d.addErrback(catchQuotaExceeded)
        d.addErrback(self._error, request)

    def _finish(self, request):
        request.write('{"success": true}')
        request.finish()

    def _error(self, e, request):
        logger.error('Error processing request: %s' % e.getErrorMessage())
        request.write('{"success": false}')
        request.setResponseCode(500)
        request.finish()


class IncomingFormatter(object):
    """
    Formats an incoming document. Today as it was by leap_mx and as expected by
    leap_mail, but the general usage should evolve towards a generic way for
    the user to receive external documents.
    """
    INCOMING_KEY = 'incoming'
    ERROR_DECRYPTING_KEY = 'errdecr'  # TODO: Always false on MX, remove it

    def format(self, raw_content, enc_scheme):
        return {self.INCOMING_KEY: True,
                self.ERROR_DECRYPTING_KEY: False,
                ENC_SCHEME_KEY: enc_scheme,
                ENC_JSON_KEY: raw_content}

    def preamble(self, raw_content, doc_id):
        rev = '0'
        scheme = preamble.ENC_SCHEME.external
        method = preamble.ENC_METHOD.pgp
        size = len(raw_content)
        raw_preamble = preamble.Preamble(doc_id, rev, scheme, method,
                                         content_size=size).encode()
        return base64.urlsafe_b64encode(raw_preamble)
