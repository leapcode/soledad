#!/usr/bin/env python


"""
This script knows how to build a minimum environment for Soledad Server, which
includes the following:

  - Couch server startup
  - Token and shared database initialization
  - Soledad Server startup

Options can be passed for configuring the different environments, so this may
be used by other programs to setup different environments for arbitrary tests.
Use the --help option to get information on usage.

For some commands you will need an environment with Soledad python packages
available, thus you might want to explicitly call python and not rely in the
shebang line.
"""


import time
import os
import signal
import tempfile
import psutil
from argparse import ArgumentParser
from subprocess import call
from couchdb import Server
from couchdb.http import PreconditionFailed
from couchdb.http import ResourceConflict
from couchdb.http import ResourceNotFound
from hashlib import sha512
from u1db.errors import DatabaseDoesNotExist


#
# Utilities
#

def get_pid(pidfile):
    if not os.path.isfile(pidfile):
        return 0
    try:
        with open(pidfile) as f:
            return int(f.read())
    except IOError:
        return 0


def pid_is_running(pid):
    try:
        psutil.Process(pid)
        return True
    except psutil.NoSuchProcess:
        return False


def pidfile_is_running(pidfile):
    try:
        pid = get_pid(pidfile)
        psutil.Process(pid)
        return pid
    except psutil.NoSuchProcess:
        return False


def status_from_pidfile(args, default_basedir):
    basedir = _get_basedir(args, default_basedir)
    pidfile = os.path.join(basedir, args.pidfile)
    try:
        pid = get_pid(pidfile)
        psutil.Process(pid)
        print "[+] running - pid: %d" % pid
    except (IOError, psutil.NoSuchProcess):
        print "[-] stopped"


def kill_all_executables(args):
    basename = os.path.basename(args.executable)
    pids = [int(pid) for pid in os.listdir('/proc') if pid.isdigit()]
    for pid in pids:
        try:
            p = psutil.Process(pid)
            if p.name() == basename:
                print '[!] killing - pid: %d' % pid
                os.kill(pid, signal.SIGKILL)
        except:
            pass


#
# Couch Server control
#

COUCH_EXECUTABLE = '/usr/bin/couchdb'
ERLANG_EXECUTABLE = 'beam.smp'
COUCH_TEMPLATE = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    './conf/couchdb_default.ini')
COUCH_TEMPLATE
COUCH_PIDFILE = 'couchdb.pid'
COUCH_LOGFILE = 'couchdb.log'
COUCH_PORT = 5984
COUCH_HOST = '127.0.0.1'
COUCH_BASEDIR = '/tmp/couch_test'


def _get_basedir(args, default):
    basedir = args.basedir
    if not basedir:
        basedir = default
    if not os.path.isdir(basedir):
        os.mkdir(basedir)
    return basedir


def couch_server_start(args):
    basedir = _get_basedir(args, COUCH_BASEDIR)
    pidfile = os.path.join(basedir, args.pidfile)
    logfile = os.path.join(basedir, args.logfile)

    # check if already running
    pid = get_pid(pidfile)
    if pid_is_running(pid):
        print '[*] error: already running - pid: %d' % pid
        exit(1)
    if os.path.isfile(pidfile):
        os.unlink(pidfile)

    # generate a config file from template if needed
    config_file = args.config_file
    if not config_file:
        config_file = tempfile.mktemp(prefix='couch_config_', dir=basedir)
        lines = []
        with open(args.template) as f:
            lines = f.readlines()
            lines = map(lambda l: l.replace('BASEDIR', basedir), lines)
        with open(config_file, 'w') as f:
            f.writelines(lines)

    # start couch server
    try:
        call([
            args.executable,
            '-n',  # reset configuration file chain (including system default)
            '-a %s' % config_file,       # add configuration FILE to chain
            '-b',  # spawn as a background process
            '-p %s' % pidfile,   # set the background PID FILE
            '-o %s' % logfile,   # redirect background stdout to FILE
            '-e %s' % logfile])  # redirect background stderr to FILE
    except Exception as e:
        print '[*] error: could not start couch server - %s' % str(e)
        exit(1)

    # couch may take a bit to store the pid in the pidfile, so we just wait
    # until it does
    pid = None
    while not pid:
        try:
            pid = get_pid(pidfile)
            break
        except:
            time.sleep(0.1)

    print '[+] running - pid: %d' % pid


def couch_server_stop(args):
    basedir = _get_basedir(args, COUCH_BASEDIR)
    pidfile = os.path.join(basedir, args.pidfile)
    pid = get_pid(pidfile)
    if not pid_is_running(pid):
        print '[*] error: no running server found'
        exit(1)
    call([
        args.executable,
        '-p %s' % pidfile,  # set the background PID FILE
        '-k'])  # kill the background process, will respawn if needed
    print '[-] stopped - pid: %d ' % pid


def couch_status_from_pidfile(args):
    status_from_pidfile(args, COUCH_BASEDIR)


#
# User DB maintenance                                                        #
#

def user_db_create(args):
    from leap.soledad.common.couch import CouchDatabase
    url = 'http://localhost:%d/user-%s' % (args.port, args.uuid)
    try:
        CouchDatabase.open_database(
            url=url, create=False, replica_uid=None, ensure_ddocs=True)
        print '[*] error: database "user-%s" already exists' % args.uuid
        exit(1)
    except DatabaseDoesNotExist:
        CouchDatabase.open_database(
            url=url, create=True, replica_uid=None, ensure_ddocs=True)
        print '[+] database created: user-%s' % args.uuid


def user_db_delete(args):
    s = _couch_get_server(args)
    try:
        dbname = 'user-%s' % args.uuid
        s.delete(dbname)
        print '[-] database deleted: %s' % dbname
    except ResourceNotFound:
        print '[*] error: database "%s" does not exist' % dbname
        exit(1)


#
# Soledad Server control
#

TWISTD_EXECUTABLE = 'twistd'  # use whatever is available on path

SOLEDAD_SERVER_BASEDIR = '/tmp/soledad_server_test'
SOLEDAD_SERVER_CONFIG_FILE = './conf/soledad_default.ini'
SOLEDAD_SERVER_PIDFILE = 'soledad.pid'
SOLEDAD_SERVER_LOGFILE = 'soledad.log'
SOLEDAD_SERVER_PRIVKEY = 'soledad_privkey.pem'
SOLEDAD_SERVER_CERTKEY = 'soledad_certkey.pem'
SOLEDAD_SERVER_PORT = 2424
SOLEDAD_SERVER_AUTH_TOKEN = 'an-auth-token'
SOLEDAD_SERVER_URL = 'https://localhost:2424'

SOLEDAD_CLIENT_PASS = '12345678'
SOLEDAD_CLIENT_BASEDIR = '/tmp/soledad_client_test'
SOLEDAD_CLIENT_UUID = '1234567890abcdef'


def soledad_server_start(args):
    basedir = _get_basedir(args, SOLEDAD_SERVER_BASEDIR)
    pidfile = os.path.join(basedir, args.pidfile)
    logfile = os.path.join(basedir, args.logfile)
    private_key = os.path.join(basedir, args.private_key)
    cert_key = os.path.join(basedir, args.cert_key)

    pid = get_pid(pidfile)
    if pid_is_running(pid):
        pid = get_pid(pidfile)
        print "[*] error: already running - pid: %d" % pid
        exit(1)

    port = args.port
    if args.tls:
        port = 'ssl:%d:privateKey=%s:certKey=%s:sslmethod=SSLv23_METHOD' \
               % (args.port, private_key, cert_key)
    params = [
        '--logfile=%s' % logfile,
        '--pidfile=%s' % pidfile,
        'web',
        '--wsgi=leap.soledad.server.application',
        '--port=%s' % port
    ]
    if args.no_daemonize:
        params.insert(0, '--nodaemon')

    call([args.executable] + params)

    pid = get_pid(pidfile)
    print '[+] running - pid: %d' % pid


def soledad_server_stop(args):
    basedir = _get_basedir(args, SOLEDAD_SERVER_BASEDIR)
    pidfile = os.path.join(basedir, args.pidfile)
    pid = get_pid(pidfile)
    if not pid_is_running(pid):
        print '[*] error: no running server found'
        exit(1)
    os.kill(pid, signal.SIGKILL)
    print '[-] stopped - pid: %d' % pid


def soledad_server_status_from_pidfile(args):
    status_from_pidfile(args, SOLEDAD_SERVER_BASEDIR)


# couch helpers

def _couch_get_server(args):
    url = 'http://%s:%d/' % (args.host, args.port)
    return Server(url=url)


def _couch_create_db(args, dbname):
    s = _couch_get_server(args)
    # maybe create the database
    try:
        s.create(dbname)
        print '[+] database created: %s' % dbname
    except PreconditionFailed as e:
        error_code, _ = e.message
        if error_code == 'file_exists':
            print '[*] error: "%s" database already exists' % dbname
            exit(1)
    return s


def _couch_delete_db(args, dbname):
    s = _couch_get_server(args)
    # maybe create the database
    try:
        s.delete(dbname)
        print '[-] database deleted: %s' % dbname
    except ResourceNotFound:
        print '[*] error: "%s" database does not exist' % dbname
        exit(1)


def _token_dbname():
    dbname = 'tokens_' + \
        str(int(time.time() / (30 * 24 * 3600)))
    return dbname


def token_db_create(args):
    dbname = _token_dbname()
    _couch_create_db(args, dbname)


def token_db_insert_token(args):
    s = _couch_get_server(args)
    try:
        dbname = _token_dbname()
        db = s[dbname]
        token = sha512(args.auth_token).hexdigest()
        db[token] = {
            'type': 'Token',
            'user_id': args.uuid,
        }
        print '[+] token for uuid "%s" created in tokens database' % args.uuid
    except ResourceConflict:
        print '[*] error: token for uuid "%s" already exists in tokens database' \
              % args.uuid
        exit(1)


def token_db_delete(args):
    dbname = _token_dbname()
    _couch_delete_db(args, dbname)


#
# Shared DB creation
#

def shared_db_create(args):
    _couch_create_db(args, 'shared')


def shared_db_delete(args):
    _couch_delete_db(args, 'shared')


#
# Certificate creation
#

CERT_CONFIG_FILE = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    './conf/cert_default.conf')


def cert_create(args):
    private_key = os.path.join(args.basedir, args.private_key)
    cert_key = os.path.join(args.basedir, args.cert_key)
    os.mkdir(args.basedir)
    call([
        'openssl',
        'req',
        '-x509',
        '-sha256',
        '-nodes',
        '-days', '365',
        '-newkey', 'rsa:2048',
        '-config', args.config_file,
        '-keyout', private_key,
        '-out', cert_key])


def cert_delete(args):
    private_key = os.path.join(args.basedir, args.private_key)
    cert_key = os.path.join(args.basedir, args.cert_key)
    os.unlink(private_key)
    os.unlink(cert_key)


#
# Soledad Client Control
#

def soledad_client_test(args):

    # maybe infer missing parameters
    basedir = args.basedir
    if not basedir:
        basedir = tempfile.mkdtemp()
    server_url = args.server_url
    if not server_url:
        server_url = 'http://127.0.0.1:%d' % args.port

    # get a soledad instance
    from client_side_db import _get_soledad_instance
    _get_soledad_instance(
        args.uuid,
        unicode(args.passphrase),
        basedir,
        server_url,
        args.cert_key,
        args.auth_token)


#
# Command Line Interface
#

class Command(object):

    def __init__(self, parser=ArgumentParser()):
        self.commands = []
        self.parser = parser
        self.subparsers = None

    def add_command(self, *args, **kwargs):
        # pop out the func parameter to use later
        func = None
        if 'func' in kwargs.keys():
            func = kwargs.pop('func')
        # eventually create a subparser
        if not self.subparsers:
            self.subparsers = self.parser.add_subparsers()
        # create command and associate a function with it
        command = Command(self.subparsers.add_parser(*args, **kwargs))
        if func:
            command.parser.set_defaults(func=func)
        self.commands.append(command)
        return command

    def set_func(self, func):
        self.parser.set_defaults(func=func)

    def add_argument(self, *args, **kwargs):
        self.parser.add_argument(*args, **kwargs)

    def add_arguments(self, arglist):
        for args, kwargs in arglist:
            self.add_argument(*args, **kwargs)

    def parse_args(self):
        return self.parser.parse_args()


#
# Command Line Interface
#

def run_cli():
    cli = Command()

    # couch command with subcommands
    cmd_couch = cli.add_command('couch', help="manage couch server")

    cmd_couch_start = cmd_couch.add_command('start', func=couch_server_start)
    cmd_couch_start.add_arguments([
        (['--executable', '-e'], {'default': COUCH_EXECUTABLE}),
        (['--basedir', '-b'], {}),
        (['--config-file', '-c'], {}),
        (['--template', '-t'], {'default': COUCH_TEMPLATE}),
        (['--pidfile', '-p'], {'default': COUCH_PIDFILE}),
        (['--logfile', '-l'], {'default': COUCH_LOGFILE})
    ])

    cmd_couch_stop = cmd_couch.add_command('stop', func=couch_server_stop)
    cmd_couch_stop.add_arguments([
        (['--executable', '-e'], {'default': COUCH_EXECUTABLE}),
        (['--basedir', '-b'], {}),
        (['--pidfile', '-p'], {'default': COUCH_PIDFILE}),
    ])

    cmd_couch_status = cmd_couch.add_command(
        'status', func=couch_status_from_pidfile)
    cmd_couch_status.add_arguments([
        (['--basedir', '-b'], {}),
        (['--pidfile', '-p'], {'default': COUCH_PIDFILE})])

    cmd_couch_kill = cmd_couch.add_command('kill', func=kill_all_executables)
    cmd_couch_kill.add_argument(
        '--executable', '-e', default=ERLANG_EXECUTABLE)

    # user database maintenance
    cmd_user_db = cli.add_command('user-db')

    cmd_user_db_create = cmd_user_db.add_command('create', func=user_db_create)
    cmd_user_db_create.add_arguments([
        (['--host', '-H'], {'default': COUCH_HOST}),
        (['--port', '-P'], {'type': int, 'default': COUCH_PORT}),
        (['--uuid', '-u'], {'default': SOLEDAD_CLIENT_UUID}),
    ])

    cmd_user_db_create = cmd_user_db.add_command(
        'delete', func=user_db_delete)
    cmd_user_db_create.add_arguments([
        (['--host', '-H'], {'default': COUCH_HOST}),
        (['--port', '-P'], {'type': int, 'default': COUCH_PORT}),
        (['--uuid', '-u'], {'default': SOLEDAD_CLIENT_UUID})
    ])

    # soledad server command with subcommands
    cmd_sol_server = cli.add_command(
        'soledad-server', help="manage soledad server")

    cmd_sol_server_start = cmd_sol_server.add_command(
        'start', func=soledad_server_start)
    cmd_sol_server_start.add_arguments([
        (['--executable', '-e'], {'default': TWISTD_EXECUTABLE}),
        (['--config-file', '-c'], {'default': SOLEDAD_SERVER_CONFIG_FILE}),
        (['--pidfile', '-p'], {'default': SOLEDAD_SERVER_PIDFILE}),
        (['--logfile', '-l'], {'default': SOLEDAD_SERVER_LOGFILE}),
        (['--port', '-P'], {'type': int, 'default': SOLEDAD_SERVER_PORT}),
        (['--tls', '-t'], {'action': 'store_true'}),
        (['--private-key', '-K'], {'default': SOLEDAD_SERVER_PRIVKEY}),
        (['--cert-key', '-C'], {'default': SOLEDAD_SERVER_CERTKEY}),
        (['--no-daemonize', '-n'], {'action': 'store_true'}),
        (['--basedir', '-b'], {'default': SOLEDAD_SERVER_BASEDIR}),
    ])

    cmd_sol_server_stop = cmd_sol_server.add_command(
        'stop', func=soledad_server_stop)
    cmd_sol_server_stop.add_arguments([
        (['--basedir', '-b'], {'default': SOLEDAD_SERVER_BASEDIR}),
        (['--pidfile', '-p'], {'default': SOLEDAD_SERVER_PIDFILE}),
    ])

    cmd_sol_server_status = cmd_sol_server.add_command(
        'status', func=soledad_server_status_from_pidfile)
    cmd_sol_server_status.add_arguments([
        (['--basedir', '-b'], {'default': SOLEDAD_SERVER_BASEDIR}),
        (['--pidfile', '-p'], {'default': SOLEDAD_SERVER_PIDFILE}),
    ])

    cmd_sol_server_kill = cmd_sol_server.add_command(
        'kill', func=kill_all_executables)
    cmd_sol_server_kill.add_argument(
        '--executable', '-e', default=TWISTD_EXECUTABLE)

    # token db maintenance
    cmd_token_db = cli.add_command('token-db')
    cmd_token_db_create = cmd_token_db.add_command(
        'create', func=token_db_create)
    cmd_token_db_create.add_arguments([
        (['--host', '-H'], {'default': COUCH_HOST}),
        (['--uuid', '-u'], {'default': SOLEDAD_CLIENT_UUID}),
        (['--port', '-P'], {'type': int, 'default': COUCH_PORT}),
    ])

    cmd_token_db_insert_token = cmd_token_db.add_command(
        'insert-token', func=token_db_insert_token)
    cmd_token_db_insert_token.add_arguments([
        (['--host', '-H'], {'default': COUCH_HOST}),
        (['--uuid', '-u'], {'default': SOLEDAD_CLIENT_UUID}),
        (['--port', '-P'], {'type': int, 'default': COUCH_PORT}),
        (['--auth-token', '-a'], {'default': SOLEDAD_SERVER_AUTH_TOKEN}),
    ])

    cmd_token_db_delete = cmd_token_db.add_command(
        'delete', func=token_db_delete)
    cmd_token_db_delete.add_arguments([
        (['--host', '-H'], {'default': COUCH_HOST}),
        (['--uuid', '-u'], {'default': SOLEDAD_CLIENT_UUID}),
        (['--port', '-P'], {'type': int, 'default': COUCH_PORT}),
    ])

    # shared db creation
    cmd_shared_db = cli.add_command('shared-db')

    cmd_shared_db_create = cmd_shared_db.add_command(
        'create', func=shared_db_create)
    cmd_shared_db_create.add_arguments([
        (['--host', '-H'], {'default': COUCH_HOST}),
        (['--port', '-P'], {'type': int, 'default': COUCH_PORT}),
    ])

    cmd_shared_db_delete = cmd_shared_db.add_command(
        'delete', func=shared_db_delete)
    cmd_shared_db_delete.add_arguments([
        (['--host', '-H'], {'default': COUCH_HOST}),
        (['--port', '-P'], {'type': int, 'default': COUCH_PORT}),
    ])

    # certificate generation
    cmd_cert = cli.add_command('cert', help="create tls certificates")

    cmd_cert_create = cmd_cert.add_command('create', func=cert_create)
    cmd_cert_create.add_arguments([
        (['--basedir', '-b'], {'default': SOLEDAD_SERVER_BASEDIR}),
        (['--config-file', '-c'], {'default': CERT_CONFIG_FILE}),
        (['--private-key', '-K'], {'default': SOLEDAD_SERVER_PRIVKEY}),
        (['--cert-key', '-C'], {'default': SOLEDAD_SERVER_CERTKEY}),
    ])

    cmd_cert_create = cmd_cert.add_command('delete', func=cert_delete)
    cmd_cert_create.add_arguments([
        (['--basedir', '-b'], {'default': SOLEDAD_SERVER_BASEDIR}),
        (['--private-key', '-K'], {'default': SOLEDAD_SERVER_PRIVKEY}),
        (['--cert-key', '-C'], {'default': SOLEDAD_SERVER_CERTKEY}),
    ])

    # soledad client command with subcommands
    cmd_sol_client = cli.add_command(
        'soledad-client', help="manage soledad client")

    cmd_sol_client_test = cmd_sol_client.add_command(
        'test', func=soledad_client_test)
    cmd_sol_client_test.add_arguments([
        (['--port', '-P'], {'type': int, 'default': SOLEDAD_SERVER_PORT}),
        (['--tls', '-t'], {'action': 'store_true'}),
        (['--uuid', '-u'], {'default': SOLEDAD_CLIENT_UUID}),
        (['--passphrase', '-k'], {'default': SOLEDAD_CLIENT_PASS}),
        (['--basedir', '-b'], {'default': SOLEDAD_CLIENT_BASEDIR}),
        (['--server-url', '-s'], {'default': SOLEDAD_SERVER_URL}),
        (['--cert-key', '-C'], {'default': os.path.join(
            SOLEDAD_SERVER_BASEDIR,
            SOLEDAD_SERVER_CERTKEY)}),
        (['--auth-token', '-a'], {'default': SOLEDAD_SERVER_AUTH_TOKEN}),
    ])

    # parse and run cli
    args = cli.parse_args()
    args.func(args)


if __name__ == '__main__':
    run_cli()
