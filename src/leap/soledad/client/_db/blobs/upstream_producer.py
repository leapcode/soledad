# -*- coding: utf-8 -*-
# upstream_producer.py
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
import json
from zope.interface import implementer
from twisted.internet import defer
from twisted.internet import reactor
from twisted.web.iweb import IBodyProducer
from twisted.web.iweb import UNKNOWN_LENGTH
from leap.soledad.client._crypto import DocInfo
from leap.soledad.client._crypto import BlobEncryptor


FIXED_REV = 'ImmutableRevision'  # Blob content is immutable


@implementer(IBodyProducer)
class BlobsUpstreamProducer(object):
    """
    Blob producer for upload streams.
    """

    def __init__(self, database, blobs_lengths, namespace, secret):
        """
        Initialize the upload streamer.

        :param database: Local blobs SQLCipher backend instance
        :type database: .sql.SQLiteBlobBackend
        :param blobs_lengths: List of blobs with ids and sizes
        :type blobs_lengths: [(blob_id:str, size:int)]
        :param namespace: Namespace which this stream belongs
        :type namespace: str
        :param secret: The secret used to encrypt blobs.
        :type secret: str
        """
        self.blobs_lengths = blobs_lengths
        self.db = database
        self.length = UNKNOWN_LENGTH
        self.pause = False
        self.stop = False
        self.namespace = namespace
        self.secret = secret

    @defer.inlineCallbacks
    def startProducing(self, consumer):
        """
        Write blobs to the consumer.

        :param consumer: Any IConsumer provider.
        :type consumer: twisted.internet.interfaces.IConsumer

        :return: A Deferred that fires when production ends.
        :rtype: twisted.internet.defer.Deferred
        """
        consumer.write(json.dumps(self.blobs_lengths) + '\n')
        for blob_id, _ in self.blobs_lengths:
            if self.stop:
                break
            if self.pause:
                yield self.sleep(0.001)
                continue
            blob_fd = yield self.db.get(blob_id, namespace=self.namespace)
            doc_info = DocInfo(blob_id, FIXED_REV)
            crypter = BlobEncryptor(doc_info, blob_fd, secret=self.secret,
                                    armor=False)
            fd = yield crypter.encrypt()
            consumer.write(fd.read())

    def sleep(self, secs):
        d = defer.Deferred()
        reactor.callLater(secs, d.callback, None)
        return d

    def pauseProducing(self):
        self.pause = True

    def stopProducing(self):
        self.stop = True

    def resumeProducing(self):
        self.pause = False
