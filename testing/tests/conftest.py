import json
import os
import pytest
import requests
import signal
import time

from hashlib import sha512
from subprocess import check_call
from urlparse import urljoin
from uuid import uuid4

from leap.soledad.common.couch import CouchDatabase
from leap.soledad.client import Soledad


#
# default options for all tests
#

DEFAULT_PASSPHRASE = '123'

DEFAULT_URL = 'http://127.0.0.1:2424'
DEFAULT_PRIVKEY = 'soledad_privkey.pem'
DEFAULT_CERTKEY = 'soledad_certkey.pem'
DEFAULT_TOKEN = 'an-auth-token'


def pytest_addoption(parser):
    parser.addoption(
        "--couch-url", type="string", default="http://127.0.0.1:5984",
        help="the url for the couch server to be used during tests")


@pytest.fixture
def couch_url(request):
    url = request.config.getoption('--couch-url')
    request.cls.couch_url = url


@pytest.fixture
def method_tmpdir(request, tmpdir):
    request.instance.tempdir = tmpdir.strpath


#
# remote_db fixture: provides an empty database for a given user in a per
# function scope.
#

class UserDatabase(object):

    def __init__(self, url, uuid):
        self._remote_db_url = urljoin(url, 'user-%s' % uuid)

    def setup(self):
        return CouchDatabase.open_database(
            url=self._remote_db_url, create=True, replica_uid=None)

    def teardown(self):
        requests.delete(self._remote_db_url)


@pytest.fixture()
def remote_db(request):
    couch_url = request.config.option.couch_url

    def create(uuid):
        db = UserDatabase(couch_url, uuid)
        request.addfinalizer(db.teardown)
        return db.setup()
    return create


def get_pid(pidfile):
    if not os.path.isfile(pidfile):
        return 0
    try:
        with open(pidfile) as f:
            return int(f.read())
    except IOError:
        return 0


#
# soledad_server fixture: provides a running soledad server in a per module
# context (same soledad server for all tests in this module).
#

class SoledadServer(object):

    def __init__(self, tmpdir_factory, couch_url):
        tmpdir = tmpdir_factory.mktemp('soledad-server')
        self._pidfile = os.path.join(tmpdir.strpath, 'soledad-server.pid')
        self._logfile = os.path.join(tmpdir.strpath, 'soledad-server.log')
        self._couch_url = couch_url

    def start(self):
        self._create_conf_file()
        # start the server
        check_call([
            'twistd',
            '--logfile=%s' % self._logfile,
            '--pidfile=%s' % self._pidfile,
            'web',
            '--class=leap.soledad.server.entrypoint.SoledadEntrypoint',
            '--port=tcp:2424'
        ])

    def _create_conf_file(self):
        if not os.access('/etc', os.W_OK):
            return
        if not os.path.isdir('/etc/soledad'):
            os.mkdir('/etc/soledad')
        with open('/etc/soledad/soledad-server.conf', 'w') as f:
            content = '[soledad-server]\ncouch_url = %s' % self._couch_url
            f.write(content)

    def stop(self):
        pid = get_pid(self._pidfile)
        os.kill(pid, signal.SIGTERM)


@pytest.fixture(scope='module')
def soledad_server(tmpdir_factory, request):
    couch_url = request.config.option.couch_url
    server = SoledadServer(tmpdir_factory, couch_url)
    server.start()
    request.addfinalizer(server.stop)
    return server


#
# soledad_dbs fixture: provides all databases needed by soledad server in a per
# module scope (same databases for all tests in this module).
#

def _token_dbname():
    dbname = 'tokens_' + \
        str(int(time.time() / (30 * 24 * 3600)))
    return dbname


class SoledadDatabases(object):

    def __init__(self, url):
        self._token_db_url = urljoin(url, _token_dbname())
        self._shared_db_url = urljoin(url, 'shared')

    def setup(self, uuid):
        self._create_dbs()
        self._add_token(uuid)

    def _create_dbs(self):
        requests.put(self._token_db_url)
        requests.put(self._shared_db_url)

    def _add_token(self, uuid):
        token = sha512(DEFAULT_TOKEN).hexdigest()
        content = {'type': 'Token', 'user_id': uuid}
        requests.put(
            self._token_db_url + '/' + token, data=json.dumps(content))

    def teardown(self):
        requests.delete(self._token_db_url)
        requests.delete(self._shared_db_url)


@pytest.fixture()
def soledad_dbs(request):
    couch_url = request.config.option.couch_url

    def create(uuid):
        db = SoledadDatabases(couch_url)
        request.addfinalizer(db.teardown)
        return db.setup(uuid)
    return create


#
# soledad_client fixture: provides a clean soledad client for a test function.
#

@pytest.fixture()
def soledad_client(tmpdir, soledad_server, remote_db, soledad_dbs, request):
    passphrase = DEFAULT_PASSPHRASE
    server_url = DEFAULT_URL
    token = DEFAULT_TOKEN
    default_uuid = uuid4().hex
    remote_db(default_uuid)
    soledad_dbs(default_uuid)

    # get a soledad instance
    def create(force_fresh_db=False):
        secrets_file = '%s.secret' % default_uuid
        secrets_path = os.path.join(tmpdir.strpath, secrets_file)

        # in some tests we might want to use the same user and remote database
        # but with a clean/empty local database (i.e. download benchmarks), so
        # here we provide a way to do that.
        db_file = '%s.db' % default_uuid
        if force_fresh_db:
            prefix = uuid4().hex
            db_file = prefix + '-' + db_file
        local_db_path = os.path.join(tmpdir.strpath, db_file)

        soledad_client = Soledad(
            default_uuid,
            unicode(passphrase),
            secrets_path=secrets_path,
            local_db_path=local_db_path,
            server_url=server_url,
            cert_file=None,
            auth_token=token)
        request.addfinalizer(soledad_client.close)
        return soledad_client
    return create
