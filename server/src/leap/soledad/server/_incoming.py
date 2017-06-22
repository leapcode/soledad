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
from twisted.web.resource import Resource
from ._config import get_config
from leap.soledad.common.couch.state import CouchServerState
from leap.soledad.common.document import ServerDocument
from leap.soledad.common.crypto import ENC_JSON_KEY
from leap.soledad.common.crypto import ENC_SCHEME_KEY
from leap.soledad.common.crypto import EncryptionSchemes


__all__ = ['IncomingResource']


def _default_backend():
    conf = get_config()
    return CouchServerState(conf['couch_url'], create_cmd=conf['create_cmd'])


class IncomingResource(Resource):
    isLeaf = True

    def __init__(self, backend_factory=None):
        self.factory = backend_factory or _default_backend()
        self.formatter = IncomingFormatter()

    def render_PUT(self, request):
        uuid, doc_id = request.postpath
        scheme = EncryptionSchemes.PUBKEY
        db = self.factory.open_database(uuid)
        doc = ServerDocument(doc_id)
        doc.content = self.formatter.format(request.content.read(), scheme)
        db.put_doc(doc)
        return '{"success": true}'


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
                ENC_SCHEME_KEY: EncryptionSchemes.NONE,
                ENC_JSON_KEY: raw_content}
