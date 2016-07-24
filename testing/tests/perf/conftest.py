import json
import os
import pytest
import requests
import signal
import time

from hashlib import sha512
from subprocess import call

from leap.soledad.client import Soledad
from leap.soledad.common.couch import CouchDatabase

from leap.common.events import server
server.ensure_server()


DEFAULT_UUID = '0'
DEFAULT_PASSPHRASE = '123'

DEFAULT_URL = 'http://127.0.0.1:2424'
DEFAULT_PRIVKEY = 'soledad_privkey.pem'
DEFAULT_CERTKEY = 'soledad_certkey.pem'
DEFAULT_TOKEN = 'an-auth-token'


@pytest.fixture
def certificate(tmpdir):
    privkey = os.path.join(tmpdir.strpath, 'privkey.pem')
    certkey = os.path.join(tmpdir.strpath, 'certkey.pem')
    call([
        'openssl',
        'req',
        '-x509',
        '-sha256',
        '-nodes',
        '-days', '365',
        '-newkey', 'rsa:2048',
        '-config', './assets/cert_default.conf',  # TODO: fix basedir
        '-keyout', privkey,
        '-out', certkey])
    return privkey, certkey


def get_pid(pidfile):
    if not os.path.isfile(pidfile):
        return 0
    try:
        with open(pidfile) as f:
            return int(f.read())
    except IOError:
        return 0


class CouchUserDatabase(object):

    def __init__(self):
        url = 'http://127.0.0.1:5984/'
        self._user_db_url = url + 'user-%s' % DEFAULT_UUID
        self._token_db_url = url + _token_dbname()
        self._shared_db_url = url + 'shared'

    def setup(self):
        CouchDatabase.open_database(
            url=self._user_db_url, create=True, replica_uid=None)
        requests.put(self._token_db_url)
        requests.put(self._shared_db_url)
        self._add_token()

    def _add_token(self):
        token = sha512(DEFAULT_TOKEN).hexdigest()
        content = {'type': 'Token', 'user_id': DEFAULT_UUID}
        requests.put(
            self._token_db_url + '/' + token, data=json.dumps(content))

    def teardown(self):
        requests.delete(self._user_db_url)
        requests.delete(self._token_db_url)
        requests.delete(self._shared_db_url)


@pytest.fixture(scope='function')
def couchdb_user_db(request):
    db = CouchUserDatabase()
    db.setup()
    request.addfinalizer(db.teardown)
    return db


def _token_dbname():
    dbname = 'tokens_' + \
        str(int(time.time() / (30 * 24 * 3600)))
    return dbname


class SoledadServer(object):

    def __init__(self, tmpdir):
        self._pidfile = os.path.join(tmpdir.strpath, 'soledad-server.pid')
        self._logfile = os.path.join(tmpdir.strpath, 'soledad-server.log')

    def start(self):
        call([
            'twistd',
            '--logfile=%s' % self._logfile,
            '--pidfile=%s' % self._pidfile,
            'web',
            '--wsgi=leap.soledad.server.application',
            '--port=2424'
        ])

    def stop(self):
        pid = get_pid(self._pidfile)
        os.kill(pid, signal.SIGKILL)


@pytest.fixture
def soledad_server(tmpdir, couchdb_user_db, request):
    server = SoledadServer(tmpdir)
    server.start()
    request.addfinalizer(server.stop)
    return server


@pytest.fixture()
def soledad_client(tmpdir, soledad_server):
    uuid = DEFAULT_UUID
    passphrase = DEFAULT_PASSPHRASE
    secrets_path = os.path.join(tmpdir.strpath, '%s.secret' % uuid)
    local_db_path = os.path.join(tmpdir.strpath, '%s.db' % uuid)
    server_url = DEFAULT_URL
    token = DEFAULT_TOKEN

    # get a soledad instance
    return Soledad(
        uuid,
        unicode(passphrase),
        secrets_path=secrets_path,
        local_db_path=local_db_path,
        server_url=server_url,
        cert_file=None,
        auth_token=token,
        defer_encryption=True)
