#!/usr/bin/python

# This script gives client-side access to one Soledad user database.

import os
import argparse
import tempfile
import getpass
import requests
import srp._pysrp as srp
import binascii
import logging
import json

from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks

from leap.soledad.client import Soledad
from leap.keymanager import KeyManager
from leap.keymanager.openpgp import OpenPGPKey

from util import ValidateUserHandle


# create a logger
logger = logging.getLogger(__name__)
LOG_FORMAT = '%(asctime)s %(message)s'
logging.basicConfig(format=LOG_FORMAT, level=logging.DEBUG)


safe_unhexlify = lambda x: binascii.unhexlify(x) if (
    len(x) % 2 == 0) else binascii.unhexlify('0' + x)


def _fail(reason):
    logger.error('Fail: ' + reason)
    exit(2)


def _get_api_info(provider):
    info = requests.get(
        'https://'+provider+'/provider.json', verify=False).json()
    return info['api_uri'], info['api_version']


def _login(username, passphrase, provider, api_uri, api_version):
    usr = srp.User(username, passphrase, srp.SHA256, srp.NG_1024)
    auth = None
    try:
        auth = _authenticate(api_uri, api_version, usr).json()
    except requests.exceptions.ConnectionError:
        _fail('Could not connect to server.')
    if 'errors' in auth:
        _fail(str(auth['errors']))
    return api_uri, api_version, auth


def _authenticate(api_uri, api_version, usr):
    api_url = "%s/%s" % (api_uri, api_version)
    session = requests.session()
    uname, A = usr.start_authentication()
    params = {'login': uname, 'A': binascii.hexlify(A)}
    init = session.post(
        api_url + '/sessions', data=params, verify=False).json()
    if 'errors' in init:
        _fail('test user not found')
    M = usr.process_challenge(
        safe_unhexlify(init['salt']), safe_unhexlify(init['B']))
    return session.put(api_url + '/sessions/' + uname, verify=False,
                       data={'client_auth': binascii.hexlify(M)})


def _get_soledad_info(username, provider, passphrase, basedir):
    api_uri, api_version = _get_api_info(provider)
    auth = _login(username, passphrase, provider, api_uri, api_version)
    # get soledad server url
    service_url = '%s/%s/config/soledad-service.json' % \
                  (api_uri, api_version)
    soledad_hosts = requests.get(service_url, verify=False).json()['hosts']
    hostnames = soledad_hosts.keys()
    # allow for choosing the host
    host = hostnames[0]
    if len(hostnames) > 1:
        i = 1
        print "There are many available hosts:"
        for h in hostnames:
            print "  (%d) %s.%s" % (i, h, provider)
            i += 1
        choice = raw_input("Choose a host to use (default: 1): ")
        if choice != '':
            host = hostnames[int(choice) - 1]
    server_url = 'https://%s:%d/user-%s' % \
              (soledad_hosts[host]['hostname'], soledad_hosts[host]['port'],
               auth[2]['id'])
    # get provider ca certificate
    ca_cert = requests.get('https://%s/ca.crt' % provider, verify=False).text
    cert_file = os.path.join(basedir, 'ca.crt')
    with open(cert_file, 'w') as f:
      f.write(ca_cert)
    return auth[2]['id'], server_url, cert_file, auth[2]['token']


def _get_soledad_instance(uuid, passphrase, basedir, server_url, cert_file,
        token):
    # setup soledad info
    logger.info('UUID is %s' % uuid)
    logger.info('Server URL is %s' % server_url)
    secrets_path = os.path.join(
        basedir, '%s.secret' % uuid)
    local_db_path = os.path.join(
        basedir, '%s.db' % uuid)
    # instantiate soledad
    return Soledad(
        uuid,
        unicode(passphrase),
        secrets_path=secrets_path,
        local_db_path=local_db_path,
        server_url=server_url,
        cert_file=cert_file,
        auth_token=token,
        defer_encryption=False)


def _get_keymanager_instance(username, provider, soledad, token,
        ca_cert_path=None, api_uri=None, api_version=None, uid=None,
        gpgbinary=None):
    return KeyManager(
        "{username}@{provider}".format(username=username, provider=provider),
        "http://uri",
        soledad,
        token=token,
        ca_cert_path=ca_cert_path,
        api_uri=api_uri,
        api_version=api_version,
        uid=uid,
        gpgbinary=gpgbinary)


def _parse_args():
    # parse command line
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'user@provider', action=ValidateUserHandle, help='the user handle')
    parser.add_argument(
        '--basedir', '-b', default=None,
        help='soledad base directory')
    parser.add_argument(
        '--passphrase', '-p', default=None,
        help='the user passphrase')
    parser.add_argument(
        '--get-all-docs', '-a', action='store_true',
        help='get all documents from the local database')
    parser.add_argument(
        '--create-doc', '-c', default=None,
        help='create a document with give content')
    parser.add_argument(
        '--sync', '-s', action='store_true',
        help='synchronize with the server replica')
    parser.add_argument(
        '--export-public-key', help="export the public key to a file")
    parser.add_argument(
        '--export-private-key', help="export the private key to a file")
    parser.add_argument(
        '--export-incoming-messages',
        help="export incoming messages to a directory")
    parser.add_argument(
        '--export-auth-data',
        help="export authentication data to a file")
    parser.add_argument(
        '--use-auth-data',
        help="use authentication data from a file")
    return parser.parse_args()


def _get_passphrase(args):
    passphrase = args.passphrase
    if passphrase is None:
        passphrase = getpass.getpass(
            'Password for %s@%s: ' % (args.username, args.provider))
    return passphrase


def _get_basedir(args):
    basedir = args.basedir
    if basedir is None:
        basedir = tempfile.mkdtemp()
    elif not os.path.isdir(basedir):
        os.mkdir(basedir)
    logger.info('Using %s as base directory.' % basedir)
    return basedir


@inlineCallbacks
def _export_key(args, km, fname, private=False):
    address = args.username + "@" + args.provider
    pkey = yield km.get_key(address, OpenPGPKey, private=private, fetch_remote=False)
    with open(args.export_private_key, "w") as f:
        f.write(pkey.key_data)


@inlineCallbacks
def _export_incoming_messages(soledad, directory):
    yield soledad.create_index("by-incoming", "bool(incoming)")
    docs = yield soledad.get_from_index("by-incoming", '1')
    i = 1
    for doc in docs:
        with open(os.path.join(directory, "message_%d.gpg" % i), "w") as f:
            f.write(doc.content["_enc_json"])
        i += 1


@inlineCallbacks
def _get_all_docs(soledad):
    _, docs = yield soledad.get_all_docs()
    for doc in docs:
        print json.dumps(doc.content, indent=4)


# main program

@inlineCallbacks
def _main(soledad, km, args):
    try:
        if args.create_doc:
            yield soledad.create_doc({'content': args.create_doc})
        if args.sync:
            yield soledad.sync()
        if args.get_all_docs:
            yield _get_all_docs(soledad)
        if args.export_private_key:
            yield _export_key(args, km, args.export_private_key, private=True)
        if args.export_public_key:
            yield _export_key(args, km, args.expoert_public_key, private=False)
        if args.export_incoming_messages:
            yield _export_incoming_messages(soledad, args.export_incoming_messages)
    except:
        pass
    finally:
        reactor.callWhenRunning(reactor.stop)


if __name__ == '__main__':
    args = _parse_args()
    passphrase = _get_passphrase(args)
    basedir = _get_basedir(args)

    if not args.use_auth_data:
        # get auth data from server
        uuid, server_url, cert_file, token = \
            _get_soledad_info(args.username, args.provider, passphrase, basedir)
    else:
        # load auth data from file
        with open(args.use_auth_data) as f:
            auth_data = json.loads(f.read())
            uuid = auth_data['uuid']
            server_url = auth_data['server_url']
            cert_file = auth_data['cert_file']
            token = auth_data['token']

    # export auth data to a file
    if args.export_auth_data:
        with open(args.export_auth_data, "w") as f:
            f.write(json.dumps({
                'uuid': uuid,
                'server_url': server_url,
                'cert_file': cert_file,
                'token': token,
            }))

    soledad = _get_soledad_instance(
        uuid, passphrase, basedir, server_url, cert_file, token)
    km = _get_keymanager_instance(
        args.username,
        args.provider,
        soledad,
        token,
        uid=uuid)
    _main(soledad, km, args)
    reactor.run()
