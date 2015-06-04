import os
import threading

from twisted.internet import reactor

from leap.mail.imap.service import imap
from leap.keymanager import KeyManager

from util import log


class IMAPServerThread(threading.Thread):
    def __init__(self, imap_service):
        threading.Thread.__init__(self)
        self._imap_service = imap_service

    def run(self):
        self._imap_service.start_loop()
        reactor.run()

    def stop(self):
        self._imap_service.stop()
        reactor.stop()


def get_imap_server(soledad, uuid, address, token):
    log("Starting imap... ", line_break=False)

    keymanager = KeyManager(address, '', soledad, token=token, uid=uuid)
    with open(
            os.path.join(
                os.path.dirname(__file__),
                'keys/5447A9AD50E3075ECCE432711B450E665FE63573.sec'), 'r') as f:
        pubkey, privkey = keymanager.parse_openpgp_ascii_key(f.read())
        keymanager.put_key(privkey)
    
    imap_service, imap_port, imap_factory = imap.run_service(
        soledad, keymanager, userid=address, offline=False)

    imap_service.start_loop()
    log("started.")
    return imap_service

    #imap_server = IMAPServerThread(imap_service)
    #try:
    #    imap_server.start()
    #except Exception as e:
    #    print str(e)
    
    #return imap_server
