import email
import json
import os
import pytest
import random
import time
import treq
import urllib

from string import ascii_lowercase
from subprocess import check_call

from twisted.internet import reactor
from twisted.internet.defer import returnValue
from twisted.web.client import Agent
from twisted.web.client import BrowserLikePolicyForHTTPS
from twisted.internet.ssl import Certificate
from twisted.cred.credentials import UsernamePassword

import pgpy
from pgpy.constants import (
    PubKeyAlgorithm,
    KeyFlags,
    HashAlgorithm,
    SymmetricKeyAlgorithm,
    CompressionAlgorithm
)

from bonafide import provider
from bonafide.session import Session

from leap.soledad.common.blobs import Flags


_provider = 'cdev.bitmask.net'

uri = "https://api.%s:4430/1/" % _provider
ca = "https://%s/ca.crt" % _provider


random.seed()


#
# session management: user creation and authentication
#

def _get_invite_code():
    invite = os.environ.get('INVITE_CODE')
    if not invite:
        raise Exception('The INVITE_CODE environment variable is empty, but '
                        'we need it set to interact with the provider.')
    return invite


@pytest.inlineCallbacks
def _get_ca_file(tmpdir):
    response = yield treq.get(ca)
    pemdata = yield response.text()
    fname = os.path.join(tmpdir.strpath, 'cacert.pem')
    with open(fname, 'w') as f:
        f.write(pemdata)
    returnValue(fname)


@pytest.inlineCallbacks
def get_session(tmpdir):
    # setup user params
    invite = _get_invite_code()
    username = ''.join(random.choice(ascii_lowercase) for i in range(20))
    # users starting with "test_user" get removed by cron on a regular basis
    username = 'tmp_user_e2e_' + username
    passphrase = ''.join(random.choice(ascii_lowercase) for i in range(20))

    # create user and login
    credentials = UsernamePassword(username, passphrase)
    api = provider.Api('https://api.%s:4430' % _provider)
    cdev_pem = yield _get_ca_file(tmpdir)
    session = Session(credentials, api, cdev_pem)
    print("creating user")
    yield session.signup(username, passphrase, invite=invite)
    print("logging in")
    yield session.authenticate()
    returnValue(session)


#
# OpenPGP key creation and upload
#

def gen_key(username):
    print("generating OpenPGP key pair")
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
    uid = pgpy.PGPUID.new(username, email='%s@%s' % (username, _provider))
    key.add_uid(
        uid,
        usage={KeyFlags.EncryptCommunications},
        hashes=[HashAlgorithm.SHA512],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.Uncompressed]
    )
    return key


@pytest.inlineCallbacks
def _get_http_client():
    response = yield treq.get(ca)
    pemdata = yield response.text()
    cert = Certificate.loadPEM(pemdata)
    policy = BrowserLikePolicyForHTTPS(trustRoot=cert)
    agent = Agent(reactor, contextFactory=policy)
    client = treq.client.HTTPClient(agent)
    returnValue(client)


@pytest.inlineCallbacks
def put_key(uuid, token, data):
    print("uploading public key to server")
    client = yield _get_http_client()
    headers = {
        'Authorization': [str('Token token=%s' % token)],
        'Content-Type': ['application/x-www-form-urlencoded'],
    }
    data = str(urllib.urlencode({'user[public_key]': data}))
    response = yield client.put(
        '%s/users/%s.json' % (uri, uuid),
        headers=headers,
        data=data)
    assert response.code == 204


#
# mail sending
#

def send_email(username):
    address = "%s@%s" % (username, _provider)
    print("sending email to %s" % address)
    secret = ''.join(random.choice(ascii_lowercase) for i in range(20))
    cmd = [
        'swaks',
        '--silent', '2',
        '--helo', 'ci.leap.se',
        '-f', 'ci@leap.se',
        '-t', address,
        '-h-Subject', 'e2e test token',
        '--body', secret,
        '-tlsc'
    ]
    check_call(cmd)
    return secret


#
# incoming message retrieval
#

@pytest.inlineCallbacks
def get_incoming_fd(client):
    pending = []
    attempts = 1
    while not pending:
        print("attempting to fetch incoming blob (%d/10)" % attempts)
        pending = yield client.blobmanager.remote_list(
            namespace='MX', filter_flags=Flags.PENDING)
        if not pending and attempts == 10:
            raise Exception("Timed out waiting for message to get delivered.")
        attempts += 1
        time.sleep(1)
    assert len(pending) == 1
    fd = yield client.blobmanager.get(pending.pop(), namespace='MX')
    returnValue(fd)


def get_received_secret(key, fd):
    print("decoding incoming blob to get the secret")
    encrypted = pgpy.PGPMessage.from_blob(fd.read())
    decrypted = key.decrypt(encrypted)
    doc_content = json.loads(decrypted.message)
    content = doc_content['content']
    email_message = email.message_from_string(content)
    received_secret = email_message.get_payload().strip()
    return received_secret
