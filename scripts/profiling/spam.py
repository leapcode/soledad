#!/usr/bin/python

# Send a lot of messages in parallel.


import string
import smtplib
import threading
import logging

from argparse import ArgumentParser


SMTP_HOST = 'chipmonk.cdev.bitmask.net'
SMTP_PORT = 465
NUMBER_OF_THREADS = 20


logger = logging.getLogger(__name__)
LOG_FORMAT = '%(asctime)s %(message)s'


def _send_email(host, port, subject, to_addr, from_addr, body_text):
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
    server = smtplib.SMTP_SSL(host, port)
    logger.info(
        "sending message: (%s, %s, %s, %i)"
        % (from_addr, to_addr, host, port))
    server.sendmail(from_addr, [to_addr], body)
    server.quit()


def _parse_args():
    parser = ArgumentParser()
    parser.add_argument(
        'target_address',
        help='The target email address to spam')
    parser.add_argument(
        'number_of_messages', type=int,
        help='The amount of messages email address to spam')
    parser.add_argument(
        '--server', '-s', default=SMTP_HOST,
        help='The SMTP server to use')
    parser.add_argument(
        '--port', '-p', default=SMTP_PORT,
        help='The SMTP port to use')
    parser.add_argument(
        '--threads', '-t', default=NUMBER_OF_THREADS,
        help='The maximum number of parallel threads to launch')
    parser.add_argument(
        '--debug', '-d', action='store_true',
        help='Print debug messages')
    return parser.parse_args()


class EmailSenderThread(threading.Thread):

    def __init__(self, host, port, subject, to_addr, from_addr, body_text,
            finished_fun):
        threading.Thread.__init__(self)
        logger.debug("initilizing thread...")
        self._host = host
        self._port = port
        self._subject = subject
        self._to_addr = to_addr
        self._from_addr = from_addr
        self._body_text = body_text
        self._finished_fun = finished_fun

    def run(self):
        logger.debug("running thread...")
        _send_email(
            self._host, self._port, self._subject, self._to_addr,
            self._from_addr, self._body_text)
        self._finished_fun()


def _launch_email_thread(host, port, subject, to_addr, from_addr, body_text,
        finished_fun):
    logger.debug("will launch email thread...")
    thread = EmailSenderThread(
        host, port, subject, to_addr, from_addr, body_text, finished_fun)
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
    host = args.server
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
               host, port, subject, to_addr, from_addr, body_text,
               _finished_fun))

    for t in threads:
        t.join()


if __name__ == "__main__":
    args = _parse_args()
    _send_messages(args)
