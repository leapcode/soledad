# -*- coding: utf-8 -*-
# send_protocol.py
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
from zope.interface import implements
from twisted.internet import defer
from twisted.internet import reactor
from twisted.web.iweb import IBodyProducer
from twisted.web.iweb import UNKNOWN_LENGTH


class DocStreamProducer(object):
    """
    A producer that writes the body of a request to a consumer.
    """

    implements(IBodyProducer)

    def __init__(self, parser_producer):
        """
        Initialize the string produer.

        :param body: The body of the request.
        :type body: str
        """
        self.body, self.producer = parser_producer
        self.length = UNKNOWN_LENGTH
        self.pause = False
        self.stop = False

    @defer.inlineCallbacks
    def startProducing(self, consumer):
        """
        Write the body to the consumer.

        :param consumer: Any IConsumer provider.
        :type consumer: twisted.internet.interfaces.IConsumer

        :return: A Deferred that fires when production ends.
        :rtype: twisted.internet.defer.Deferred
        """
        call = self.producer.pop(0)
        yield call[0](*call[1:])
        while self.producer and not self.stop:
            if self.pause:
                yield self.sleep(0.001)
                continue
            call = self.producer.pop(0)
            yield call[0](*call[1:])
            consumer.write(self.body.pop(1))
        consumer.write(self.body.pop(1))

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
