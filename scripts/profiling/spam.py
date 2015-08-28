#!/usr/bin/python

# Send a lot of messages in parallel.


import string
import smtplib
import threading
import logging
import dns.resolver

from argparse import ArgumentParser


SMTP_DEFAULT_PORT = 465
NUMBER_OF_THREADS = 20


logger = logging.getLogger(__name__)
LOG_FORMAT = '%(asctime)s %(message)s'


def _send_email(server, port, subject, to_addr, from_addr, body_text):
    """
    Send an email
    """
    body = string.join((
            "From: %s" % from_addr,
            "To: %s" % to_addr,
            "Subject: %s" % subject,
            "",
            body_text
            ), "\r\n")
    logger.debug("setting up smtp...")
    smtp = smtplib.SMTP_SSL(server, port)
    logger.info(
        "sending message: (%s, %s, %s, %i)"
        % (from_addr, to_addr, server, port))
    smtp.sendmail(from_addr, [to_addr], body)
    smtp.quit()


def _parse_args():
    parser = ArgumentParser()
    parser.add_argument(
        'target_address',
        help='The target email address to spam')
    parser.add_argument(
        'number_of_messages', type=int,
        help='The amount of messages email address to spam')
    parser.add_argument(
        '--server', '-s',
        help='The SMTP server to use')
    parser.add_argument(
        '--port', '-p', default=SMTP_DEFAULT_PORT,
        help='The SMTP port to use')
    parser.add_argument(
        '--threads', '-t', default=NUMBER_OF_THREADS,
        help='The maximum number of parallel threads to launch')
    parser.add_argument(
        '--debug', '-d', action='store_true',
        help='Print debug messages')
    return parser.parse_args()


class EmailSenderThread(threading.Thread):

    def __init__(self, server, port, subject, to_addr, from_addr, body_text,
                 finished_fun):
        threading.Thread.__init__(self)
        logger.debug("initilizing thread...")
        self._server = server
        self._port = port
        self._subject = subject
        self._to_addr = to_addr
        self._from_addr = from_addr
        self._body_text = body_text
        self._finished_fun = finished_fun

    def run(self):
        logger.debug("running thread...")
        try:
            _send_email(
                self._server, self._port, self._subject, self._to_addr,
                self._from_addr, self._body_text)
        except Exception as e:
            logger.error(e)
        finally:
            self._finished_fun()


def _launch_email_thread(server, port, subject, to_addr, from_addr, body_text,
                         finished_fun):
    logger.debug("will launch email thread...")
    thread = EmailSenderThread(
        server, port, subject, to_addr, from_addr, body_text, finished_fun)
    thread.start()
    return thread


class FinishedThreads(object):

    def __init__(self):
        self._finished = 0
        self._lock = threading.Lock()

    def signal(self):
        with self._lock:
            self._finished = self._finished + 1
            logger.info('number of messages sent: %d.' % self._finished)


def _send_messages(args):
    server = args.server
    port = args.port
    subject = "Message from Soledad script"
    to_addr = args.target_address
    from_addr = args.target_address
    body_text = "Test message"

    # configure log level
    if args.debug:
        level = logging.DEBUG
    else:
        level = logging.INFO
    logging.basicConfig(format=LOG_FORMAT, level=level)

    # get MX configuration
    if not server:
        logger.info("Resolving MX server...")
        _, domain = to_addr.split("@", 1)
        result = dns.resolver.query(domain, "MX")
        server = result[0].exchange.to_text()
        logger.info("MX server is: %s" % server)

    semaphore = threading.Semaphore(args.threads)
    threads = []
    finished_threads = FinishedThreads()

    def _finished_fun():
        semaphore.release()
        finished_threads.signal()

    for i in xrange(args.number_of_messages):
        semaphore.acquire()
        threads.append(
            _launch_email_thread(
               server, port, subject, to_addr, from_addr, body_text,
               _finished_fun))

    for t in threads:
        t.join()


if __name__ == "__main__":
    args = _parse_args()
    _send_messages(args)
