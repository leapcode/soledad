"""
A U1DB server that stores data using couchdb.

This should be run with:
    twistd -n web --wsgi=leap.soledad.server.application
"""

import configparser
from twisted.web.wsgi import WSGIResource
from twisted.internet import reactor
from u1db.remote import http_app
from leap.soledad.backends.couch import CouchServerState


def load_configuration(file_path):
    conf = {
        'couch_url': 'http://localhost:5984',
        'working_dir': '/tmp',
    }
    config = configparser.ConfigParser()
    config.read(file_path)
    if 'soledad-server' in config:
        for key in conf:
            if key in config['soledad-server']:
                conf[key] = config['soledad-server'][key]
    return conf


conf = load_configuration('/etc/leap/soledad-server.ini')

state = CouchServerState(conf['couch_url'])
# TODO: change working dir to something meaningful
state.set_workingdir(conf['working_dir'])
application = http_app.HTTPApp(state)

resource = WSGIResource(reactor, reactor.getThreadPool(), application)
