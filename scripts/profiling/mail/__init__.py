import threading
import time
import logging
import argparse

from twisted.internet import reactor

from util import log
from couchdb_server import get_couchdb_wrapper_and_u1db
from mx import put_lots_of_messages
from soledad_server import get_soledad_server
from soledad_client import SoledadClient
from mail import get_imap_server


UUID = 'blah'
AUTH_TOKEN = 'bleh'


logging.basicConfig(level=logging.DEBUG)

modules = [
    'gnupg',
    'leap.common',
    'leap.keymanager',
    'taskthread',
]

for module in modules:
    logger = logging.getLogger(name=module)
    logger.setLevel(logging.WARNING)


class TestWatcher(threading.Thread):

    def __init__(self, couchdb_wrapper, couchdb_u1db, soledad_server,
            soledad_client, imap_service, number_of_msgs, lock):
        threading.Thread.__init__(self)
        self._couchdb_wrapper = couchdb_wrapper
        self._couchdb_u1db = couchdb_u1db
        self._soledad_server = soledad_server
        self._soledad_client = soledad_client
        self._imap_service = imap_service
        self._number_of_msgs = number_of_msgs
        self._lock = lock
        self._mails_available_time = None
        self._mails_available_time_lock = threading.Lock()
        self._conditions = None

    def run(self):
        self._set_conditions()
        while not self._test_finished():
            time.sleep(5)
        log("TestWatcher: Tests finished, cleaning up...",
            line_break=False)
        self._stop_reactor()
        self._cleanup()
        log("done.")
        self._lock.release()

    def _set_conditions(self):
        self._conditions = []

        # condition 1: number of received messages is equal to number of
        # expected messages
        def _condition1(*args):
            msgcount = self._imap_service._inbox.getMessageCount()
            cond = msgcount == self._number_of_msgs
            log("[condition 1] received messages: %d (expected: %d) :: %s"
                % (msgcount, self._number_of_msgs, cond))
            if self.mails_available_time == None \
                    and cond:
                with self._mails_available_time_lock:
                    self._mails_available_time = time.time()
            return cond


        # condition 2: number of documents in server is equal to in client
        def _condition2(client_docs, server_docs):
            cond = client_docs == server_docs
            log("[condition 2] number of documents: client %d; server %d :: %s"
                % (client_docs, server_docs, cond))
            return cond

        # condition 3: number of documents bigger than 3 x number of msgs
        def _condition3(client_docs, *args):
            cond = client_docs > (2 * self._number_of_msgs)
            log("[condition 3] documents (%d) > 2 * msgs (%d) :: %s"
                % (client_docs, self._number_of_msgs, cond))
            return cond

        # condition 4: not syncing
        def _condition4(*args):
            cond = not self._soledad_client.instance.syncing
            log("[condition 4] not syncing :: %s" % cond)
            return cond

        self._conditions.append(_condition1)
        self._conditions.append(_condition2)
        self._conditions.append(_condition3)
        self._conditions.append(_condition4)

    def _test_finished(self):
        client_docs = self._get_soledad_client_number_of_docs()
        server_docs = self._get_couchdb_number_of_docs()
        return not bool(filter(lambda x: not x(client_docs, server_docs),
                               self._conditions))

    def _stop_reactor(self):
        reactor.stop()

    def _cleanup(self):
        self._imap_service.stop()
        self._soledad_client.close()
        self._soledad_server.stop()
        self._couchdb_wrapper.stop()

    def _get_soledad_client_number_of_docs(self):
        c = self._soledad_client.instance._db._db_handle.cursor()
        c.execute('SELECT COUNT(*) FROM document WHERE content IS NOT NULL')
        row = c.fetchone()
        return int(row[0])

    def _get_couchdb_number_of_docs(self):
        couchdb = self._couchdb_u1db._database
        view = couchdb.view('_all_docs', include_docs=True)
        return len(filter(
            lambda r: '_attachments' in r.values()[1]
                and 'u1db_content' in r.values()[1]['_attachments'],
            view.rows))

    @property
    def mails_available_time(self):
        with self._mails_available_time_lock:
            return self._mails_available_time


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('number_of_msgs', help="The number of documents",
        type=int)
    parser.add_argument('report_file', help="The name of the report file",
        type=str)
    args = parser.parse_args()

    # start a couchdb server
    couchdb_wrapper, couchdb_u1db = get_couchdb_wrapper_and_u1db(
        UUID, AUTH_TOKEN)

    put_time = put_lots_of_messages(couchdb_u1db, args.number_of_msgs)

    soledad_server = get_soledad_server(couchdb_wrapper.port)

    soledad_client = SoledadClient(
        uuid='blah',
        server_url='http://127.0.0.1:%d' % soledad_server.port,
        auth_token=AUTH_TOKEN)

    imap_service = get_imap_server(
        soledad_client.instance, UUID, 'snowden@bitmask.net', AUTH_TOKEN)

    lock = threading.Lock()
    lock.acquire()
    test_watcher = TestWatcher(
        couchdb_wrapper, couchdb_u1db, soledad_server, soledad_client,
        imap_service, args.number_of_msgs, lock)
    test_watcher.start()

    # reactor.run() will block until TestWatcher stops the reactor.
    start_time = time.time()
    reactor.run()
    log("Reactor stopped.")
    end_time = time.time()
    lock.acquire()
    mails_available_time = test_watcher.mails_available_time - start_time
    sync_time = end_time - start_time
    log("Total syncing time: %f" % sync_time)
    log("# number_of_msgs put_time mails_available_time sync_time")
    result = "%d %f %f %f" \
             % (args.number_of_msgs, put_time, mails_available_time,
                sync_time)
    log(result)
    with open(args.report_file, 'a') as f:
        f.write(result + "\n")
