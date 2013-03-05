"""
A U1DB server that stores data using couchdb.

This should be run with:
    twistd -n web --wsgi=leap.soledad.server.application
"""

import configparser
from wsgiref.util import shift_path_info
import httplib
try:
    import simplejson as json
except ImportError:
    import json  # noqa
from urlparse import parse_qs

from twisted.web.wsgi import WSGIResource
from twisted.internet import reactor

from u1db.remote import http_app

from leap.soledad.backends.couch import CouchServerState


#-----------------------------------------------------------------------------
# Authentication
#-----------------------------------------------------------------------------

class Unauthorized(Exception):
    """
    User authentication failed.
    """


class SoledadAuthMiddleware(object):
    """
    Soledad Authentication WSGI middleware.

    In general, databases are accessed using a token provided by the LEAP API.
    Some special databases can be read without authentication.
    """

    def __init__(self, app, prefix, public_dbs=None):
        self.app = app
        self.prefix = prefix
        self.public_dbs = public_dbs

    def _error(self, start_response, status, description, message=None):
        start_response("%d %s" % (status, httplib.responses[status]),
                       [('content-type', 'application/json')])
        err = {"error": description}
        if message:
            err['message'] = message
        return [json.dumps(err)]

    def __call__(self, environ, start_response):
        if self.prefix and not environ['PATH_INFO'].startswith(self.prefix):
            return self._error(start_response, 400, "bad request")
        shift_path_info(environ)
        qs = parse_qs(environ.get('QUERY_STRING'), strict_parsing=True)
        if 'auth_token' not in qs:
            if self.need_auth(environ):
                return self._error(start_response, 401, "unauthorized",
                                   "Missing Authentication Token.")
        else:
            token = qs['auth_token'][0]
            try:
                self.verify_token(environ, token)
            except Unauthorized:
                return self._error(
                    start_response, 401, "unauthorized",
                    "Incorrect password or login.")
            # remove auth token from query string.
            del qs['auth_token']
            qs_str = ''
            if qs:
                qs_str = reduce(lambda x, y: '&'.join([x, y]),
                                map(lambda (x, y): '='.join([x, str(y)]),
                                    qs.iteritems()))
            environ['QUERY_STRING'] = qs_str
        return self.app(environ, start_response)

    def verify_token(self, environ, token):
        """
        Verify if token is valid for authenticating this action.
        """
        # TODO: implement token verification
        raise NotImplementedError(self.verify_token)

    def need_auth(self, environ):
        """
        Check if action can be performed on database without authentication.

        For now, just allow access to /shared/*.
        """
        # TODO: design unauth verification.
        return not environ.get('PATH_INFO').startswith('/shared/')


#-----------------------------------------------------------------------------
# Soledad WSGI application
#-----------------------------------------------------------------------------

class SoledadApp(http_app.HTTPApp):
    """
    Soledad WSGI application
    """

    def __call__(self, environ, start_response):
        return super(SoledadApp, self).__call__(environ, start_response)


#-----------------------------------------------------------------------------
# Auxiliary functions
#-----------------------------------------------------------------------------

def load_configuration(file_path):
    conf = {
        'couch_url': 'http://localhost:5984',
        'working_dir': '/tmp',
        'public_dbs': 'keys',
        'prefix': '/soledad/',
    }
    config = configparser.ConfigParser()
    config.read(file_path)
    if 'soledad-server' in config:
        for key in conf:
            if key in config['soledad-server']:
                conf[key] = config['soledad-server'][key]
    # TODO: implement basic parsing of options comming from config file.
    return conf


#-----------------------------------------------------------------------------
# Run as Twisted WSGI Resource
#-----------------------------------------------------------------------------

# TODO: create command-line option for choosing config file.
conf = load_configuration('/etc/leap/soledad-server.ini')
state = CouchServerState(conf['couch_url'])
# TODO: change working dir to something meaningful (maybe eliminate it)
state.set_workingdir(conf['working_dir'])

application = SoledadAuthMiddleware(
    SoledadApp(state),
    conf['prefix'],
    conf['public_dbs'].split(','))

resource = WSGIResource(reactor, reactor.getThreadPool(), application)
