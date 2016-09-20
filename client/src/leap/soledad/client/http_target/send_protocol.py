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

        :return: A successful deferred.
        :rtype: twisted.internet.defer.Deferred
        """
        call = self.producer.pop(0)
        yield call[0](*call[1:])
        while self.producer and not self.stop:
            if self.pause:
                yield self.sleep(0.01)
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
