import binascii
import hashlib
import hmac
import os

from cStringIO import StringIO

from twisted.persisted import dirdbm
from twisted.internet import defer
from twisted.internet import interfaces
from twisted.internet import reactor
from twisted.web import client
from twisted.web.client import FileBodyProducer

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends.multibackend import MultiBackend
from cryptography.hazmat.backends.openssl.backend \
    import Backend as OpenSSLBackend

from zope.interface import implements

from leap.common.config import get_path_prefix
from leap.soledad.client.secrets import SoledadSecrets


MAC_KEY_LENGTH = 64

crypto_backend = MultiBackend([OpenSSLBackend()])


class AESWriter(object):

    implements(interfaces.IConsumer)

    def __init__(self, key, fd, iv=None):
        if iv is None:
            iv = os.urandom(16)

        cipher = _get_aes_ctr_cipher(key, iv)
        self.encryptor = cipher.encryptor()

        self.fd = fd
        self.done = False
        self.deferred = defer.Deferred()

    def write(self, data):
        encrypted = self.encryptor.update(data)
        self.fd.write(encrypted)
        return encrypted

    def end(self):
        if not self.done:
            self.encryptor.finalize()
            self.fd.seek(0)
            self.deferred.callback(self.fd)
        self.done = True


class HMACWriter(object):

    implements(interfaces.IConsumer)

    def __init__(self, key):
        self.done = False
        self.deferred = defer.Deferred()

        self.digest = ''
        self._hmac = hmac.new(key, '', hashlib.sha256)

    def write(self, data):
        self._hmac.update(data)

    def end(self):
        if not self.done:
            self.digest = self._hmac.digest()
            self.deferred.callback(self.digest)
        self.done = True


class EncryptAndHMAC(object):

    implements(interfaces.IConsumer)

    def __init__(self, crypter, hmac):
        self.crypter = crypter
        self.hmac = hmac

    def write(self, data):
        enc_chunk = self.crypter.write(data)
        self.hmac.write(enc_chunk)
        


class NewDocCryptoStreamer(object):

    staging_path = os.path.join(get_path_prefix(), 'leap', 'soledad', 'staging')
    staged_template = """
     {"_enc_scheme": "symkey",
      "_enc_method": "aes-256-ctr",
      "_mac_method": "hmac",
      "_mac_hash": "sha256",
      "_encoding": "ENCODING",
      "_enc_json": "ENC",
      "_enc_iv": "IV",
      "_mac": "MAC"}"""


    def __init__(self, content_fd, doc_id, rev, secret=None):
        self._content_fd  = content_fd
        self._contentFileProducer = FileBodyProducer(
            content_fd, readSize=2**8)
        self.doc_id = doc_id
        self.rev = rev
        self._encrypted_fd = StringIO()

        self.iv = os.urandom(16)

        sym_key = _get_sym_key_for_doc(doc_id, secret)
        mac_key = _get_mac_key_for_doc(doc_id, secret)

        crypter = AESWriter(sym_key, self._encrypted_fd, self.iv)
        hmac = HMACWriter(mac_key)

        self.crypter_consumer = crypter
        self.hmac_consumer = hmac

        self._prime_hmac()
        self.encrypt_and_mac_consumer = EncryptAndHMAC(crypter, hmac)

    def encrypt_stream(self):
        d = self._contentFileProducer.startProducing(
            self.encrypt_and_mac_consumer)
        d.addCallback(self.end_crypto_stream)
        d.addCallback(self.persist_encrypted_doc)
        return d

    def end_crypto_stream(self, ignored):
        self.crypter_consumer.end()
        self._post_hmac()
        self.hmac_consumer.end()
        return defer.succeed('ok')

    def persist_encrypted_doc(self, ignored, encoding='hex'):
        # TODO to avoid blocking on io, this can use a
        # version of dbm that chunks the writes to the 
        # disk fd by using the same FileBodyProducer strategy
        # that we're using here, long live to the Cooperator.
        # this will benefit 

        # TODO -- transition to hex: needs migration FIXME
        if encoding == 'b64':
            encode = binascii.b2a_base64
        elif encoding == 'hex':
            encode = binascii.b2a_hex
        else:
            raise RuntimeError('Unknown encoding: %s' % encoding)

        db = dirdbm.DirDBM(self.staging_path)
        key = '{doc_id}@{rev}'.format(
            doc_id=self.doc_id, rev=self.rev)
        value = self.staged_template.replace(
            'ENCODING', encoding).replace(
            'ENC', encode(self._encrypted_fd.read())).replace(
            'IV', binascii.b2a_base64(self.iv)).replace(
            'MAC', encode(self.hmac_consumer.digest))
        db[key] = value

        self._content_fd.close()
        self._encrypted_fd.close()

    def _prime_hmac(self):
        pre = '{doc_id}{rev}'.format(
            doc_id=self.doc_id, rev=self.rev)
        self.hmac_consumer.write(pre)

    def _post_hmac(self):
        # FIXME -- original impl passed b64 encoded iv
        post = '{enc_scheme}{enc_method}{enc_iv}'.format(
            enc_scheme='symkey',
            enc_method='aes-256-ctr',
            enc_iv=binascii.b2a_base64(self.iv))
        self.hmac_consumer.write(post)


def _hmac_sha256(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()


def _get_mac_key_for_doc(doc_id, secret):
    key = secret[:MAC_KEY_LENGTH]
    return _hmac_sha256(key, doc_id)


def _get_sym_key_for_doc(doc_id, secret):
    key = secret[MAC_KEY_LENGTH:]
    return _hmac_sha256(key, doc_id)


def _get_aes_ctr_cipher(key, iv):
    return Cipher(algorithms.AES(key), modes.CTR(iv), backend=crypto_backend)
