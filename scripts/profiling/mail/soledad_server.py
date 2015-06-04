import threading

from wsgiref.simple_server import make_server

from leap.soledad.common.couch import CouchServerState

from leap.soledad.server import SoledadApp
from leap.soledad.server.gzip_middleware import GzipMiddleware
from leap.soledad.server.auth import SoledadTokenAuthMiddleware

from util import log


class SoledadServerThread(threading.Thread):
    def __init__(self, server):
        threading.Thread.__init__(self)
        self._server = server

    def run(self):
        self._server.serve_forever()

    def stop(self):
        self._server.shutdown()

    @property
    def port(self):
        return self._server.server_port


def make_soledad_server_thread(couch_port):
    state = CouchServerState(
        'http://127.0.0.1:%d' % couch_port,
        'shared',
        'tokens')
    application = GzipMiddleware(
        SoledadTokenAuthMiddleware(SoledadApp(state)))
    server = make_server('', 0, application)
    t = SoledadServerThread(server)
    return t


def get_soledad_server(couchdb_port):
    log("Starting soledad server... ", line_break=False)
    soledad_server = make_soledad_server_thread(couchdb_port)
    soledad_server.start()
    log("soledad server started on port %d." % soledad_server.port)
    return soledad_server

