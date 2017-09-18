import glob
import base64
import json
import os
import pytest
import re
import random
import requests
import signal
import socket
import subprocess
import sys
import time

from hashlib import sha512
from six.moves.urllib.parse import urljoin
from six.moves.urllib.parse import urlsplit
from uuid import uuid4

from leap.soledad.common.couch import CouchDatabase
from leap.soledad.client import Soledad


def _select_subdir(subdir, blacklist, items):

    # allow blacklisted subdir if explicited in command line
    if subdir and subdir in blacklist:
        blacklist.remove(subdir)

    # determine blacklisted subdirs
    dirname = os.path.dirname(__file__)
    blacklisted_subdirs = map(lambda s: os.path.join(dirname, s), blacklist)

    # determine base path for selected tests
    path = dirname
    if subdir:
        path = os.path.join(dirname, subdir)

    # remove tests from blacklisted subdirs
    selected = []
    deselected = []
    for item in items:
        filename = item.module.__file__
        blacklisted = any(
            map(lambda s: filename.startswith(s), blacklisted_subdirs))
        if blacklisted or not filename.startswith(path):
            deselected.append(item)
        else:
            selected.append(item)

    return selected, deselected


def pytest_collection_modifyitems(items, config):

    # mark tests that depend on couchdb
    marker = getattr(pytest.mark, 'needs_couch')
    for item in items:
        if 'soledad/testing/tests/couch/' in item.module.__file__:
            item.add_marker(marker)

    # select/deselect tests based on a blacklist and the subdir option given in
    # command line
    blacklist = ['benchmarks', 'responsiveness', 'e2e']
    subdir = config.getoption('subdir')
    selected, deselected = _select_subdir(subdir, blacklist, items)
    config.hook.pytest_deselected(items=deselected)
    items[:] = selected


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

    # the following options are only used in benchmarks, but has to be defined
    # here due to how pytest discovers plugins during startup.
    parser.addoption(
        "--watch-memory", default=False, action="store_true",
        help="whether to monitor memory percentages during test run. "
             "**Warning**: enabling this will impact the time taken and the "
             "CPU used by the benchmarked code, so use with caution!")

    parser.addoption(
        "--soledad-server-url", type="string", default=None,
        help="Soledad Server URL. A local server will be started if and only "
             "if  no URL is passed.")

    # the following option is only used in responsiveness tests, but has to be
    # defined here due to how pytest discovers plugins during startup.
    parser.addoption(
        "--elasticsearch-url", type="string", default=None,
        help="the url for posting responsiveness results to elasticsearch")

    parser.addoption(
        "--subdir", type="string", default=None,
        help="select only tests from a certain subdirectory of ./tests/")


def _request(method, url, data=None, do=True):
    if do:
        method = getattr(requests, method)
        method(url, data=data)
    else:
        cmd = 'curl --netrc -X %s %s' % (method.upper(), url)
        if data:
            cmd += ' -d "%s"' % json.dumps(data)
        print(cmd)


@pytest.fixture
def couch_url(request):
    url = request.config.option.couch_url
    request.cls.couch_url = url


@pytest.fixture
def method_tmpdir(request, tmpdir):
    request.instance.tempdir = tmpdir.strpath


#
# remote_db fixture: provides an empty database for a given user in a per
# function scope.
#

class UserDatabase(object):

    def __init__(self, url, uuid, create=True):
        self._remote_db_url = urljoin(url, 'user-%s' % uuid)
        self._create = create

    def setup(self):
        if self._create:
            return CouchDatabase.open_database(
                url=self._remote_db_url, create=True, replica_uid=None)
        else:
            _request('put', self._remote_db_url, do=False)

    def teardown(self):
        _request('delete', self._remote_db_url, do=self._create)


@pytest.fixture()
def remote_db(request):
    couch_url = request.config.option.couch_url

    def create(uuid, create=True):
        db = UserDatabase(couch_url, uuid, create=create)
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
        self.tmpdir = tmpdir
        self._pidfile = os.path.join(tmpdir.strpath, 'soledad-server.pid')
        self._logfile = os.path.join(tmpdir.strpath, 'soledad-server.log')
        self._couch_url = couch_url

    def start(self):
        self._create_conf_file()
        # start the server
        executable = 'twistd'
        if 'VIRTUAL_ENV' not in os.environ:
            executable = os.path.join(
                os.path.dirname(os.environ['_']), 'twistd')
        subprocess.check_call([
            executable,
            '--logfile=%s' % self._logfile,
            '--pidfile=%s' % self._pidfile,
            'web',
            '--class=leap.soledad.server.entrypoints.SoledadEntrypoint',
            '--port=tcp:2424'
        ])

    def _create_conf_file(self):

        # come up with name of the configuration file
        fname = '/etc/soledad/soledad-server.conf'
        if not os.access('/etc', os.W_OK):
            fname = os.path.join(self.tmpdir.strpath, 'soledad-server.conf')

        # create the configuration file
        dirname = os.path.dirname(fname)
        if not os.path.isdir(dirname):
            os.mkdir(dirname)
        with open(fname, 'w') as f:
            blobs_path = os.path.join(str(self.tmpdir), 'blobs')
            content = '''[soledad-server]
couch_url = %s
blobs = true
blobs_path = %s''' % (self._couch_url, blobs_path)
            f.write(content)

        # update the environment to use that file
        os.environ.update({'SOLEDAD_SERVER_CONFIG_FILE': fname})

    def stop(self):
        pid = get_pid(self._pidfile)
        os.kill(pid, signal.SIGTERM)


@pytest.fixture(scope='module')
def soledad_server(tmpdir_factory, request):

    # avoid starting a server if the url is remote
    soledad_url = request.config.option.soledad_server_url
    if soledad_url is not None:
        return None

    # start a soledad server
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

    def __init__(self, url, create=True):
        self._token_db_url = urljoin(url, _token_dbname())
        self._shared_db_url = urljoin(url, 'shared')
        self._create = create

    def setup(self, uuid):
        self._create_dbs()
        self._add_token(uuid)

    def _create_dbs(self):
        _request('put', self._token_db_url, do=self._create)
        _request('put', self._shared_db_url, do=self._create)

    def _add_token(self, uuid):
        token = sha512(DEFAULT_TOKEN).hexdigest()
        content = {'type': 'Token', 'user_id': uuid}
        _request('put', self._token_db_url + '/' + token,
                 data=json.dumps(content), do=self._create)

    def teardown(self):
        _request('delete', self._token_db_url, do=self._create)
        _request('delete', self._shared_db_url, do=self._create)


@pytest.fixture()
def soledad_dbs(request):
    couch_url = request.config.option.couch_url

    def create(uuid, create=True):
        db = SoledadDatabases(couch_url, create=create)
        request.addfinalizer(db.teardown)
        return db.setup(uuid)
    return create


#
# soledad_client fixture: provides a clean soledad client for a test function.
#

def _get_certfile(url, tmpdir):

    # download the certificate
    parsed = urlsplit(url)
    netloc = re.sub('^[^\.]+\.', '', parsed.netloc)
    host, _ = netloc.split(':')
    response = requests.get('https://%s/ca.crt' % host, verify=False)

    # store it in a temporary file
    cert_file = os.path.join(tmpdir.strpath, 'cert.pem')
    with open(cert_file, 'w') as f:
        f.write(response.text)

    return cert_file


@pytest.fixture()
def soledad_client(tmpdir, soledad_server, remote_db, soledad_dbs, request):

    # default values for local server
    server_url = DEFAULT_URL
    default_uuid = uuid4().hex
    create = True
    cert_file = None

    # use values for remote server if server url is passed
    url_arg = request.config.option.soledad_server_url
    if url_arg:
        server_url = url_arg
        default_uuid = 'test-user'
        create = False
        cert_file = _get_certfile(server_url, tmpdir)

    remote_db(default_uuid, create=create)
    soledad_dbs(default_uuid, create=create)

    # get a soledad instance
    def create(force_fresh_db=False, uuid=default_uuid,
               passphrase=DEFAULT_PASSPHRASE, token=DEFAULT_TOKEN):

        secrets_file = '%s.secret' % uuid
        secrets_path = os.path.join(tmpdir.strpath, secrets_file)

        # in some tests we might want to use the same user and remote database
        # but with a clean/empty local database (i.e. download benchmarks), so
        # here we provide a way to do that.
        idx = 1
        if force_fresh_db:
            # find the next index for this user
            idx = len(glob.glob('%s/*-*.db' % tmpdir.strpath)) + 1
        db_file = '%s-%d.db' % (uuid, idx)
        local_db_path = os.path.join(tmpdir.strpath, db_file)

        soledad_client = Soledad(
            uuid,
            unicode(passphrase),
            secrets_path=secrets_path,
            local_db_path=local_db_path,
            server_url=server_url,
            cert_file=cert_file,
            auth_token=token,
            with_blobs=True)
        request.addfinalizer(soledad_client.close)
        return soledad_client
    return create


#
# pytest-benchmark customizations
#

# avoid hooking if this is not a benchmarking environment
if 'pytest_benchmark' in sys.modules:

    def pytest_benchmark_update_machine_info(config, machine_info):
        """
        Add the host's hostname information to machine_info.

        Get the value from the HOST_HOSTNAME environment variable if it is set,
        or from the actual system's hostname otherwise.
        """
        hostname = os.environ.get('HOST_HOSTNAME', socket.gethostname())
        machine_info['host'] = hostname


#
# benchmark/responsiveness fixtures
#

@pytest.fixture()
def payload():
    def generate(size):
        random.seed(1337)  # same seed to avoid different bench results
        payload_bytes = bytearray(random.getrandbits(8) for _ in xrange(size))
        # encode as base64 to avoid ascii encode/decode errors
        return base64.b64encode(payload_bytes)[:size]  # remove b64 overhead
    return generate
