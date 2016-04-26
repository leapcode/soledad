import datetime
import uuid
import json
import timeit


from leap.keymanager import openpgp
from leap.soledad.common.document import ServerDocument
from leap.soledad.common.crypto import (
    EncryptionSchemes,
    ENC_JSON_KEY,
    ENC_SCHEME_KEY,
)


from util import log


message = """To: Ed Snowden <snowden@bitmask.net>
Date: %s
From: Glenn Greenwald <greenwald@bitmask.net>

hi!

"""


def get_message():
    return message % datetime.datetime.now().strftime("%a %b %d %H:%M:%S:%f %Y")


def get_enc_json(pubkey, message):
    with openpgp.TempGPGWrapper(gpgbinary='/usr/bin/gpg') as gpg:
        gpg.import_keys(pubkey)
        key = gpg.list_keys().pop()
        # We don't care about the actual address, so we use a
        # dummy one, we just care about the import of the pubkey
        openpgp_key = openpgp._build_key_from_gpg("dummy@mail.com",
                                                  key, pubkey)
        enc_json = str(gpg.encrypt(
            json.dumps(
                {'incoming': True, 'content': message},
                ensure_ascii=False),
            openpgp_key.fingerprint,
            symmetric=False))
    return enc_json


def get_new_doc(enc_json):
    doc = ServerDocument(doc_id=str(uuid.uuid4()))
    doc.content = {
        'incoming': True,
        ENC_SCHEME_KEY: EncryptionSchemes.PUBKEY,
        ENC_JSON_KEY: enc_json
    }
    return doc


def get_pubkey():
    with open('./keys/5447A9AD50E3075ECCE432711B450E665FE63573.pub') as f:
        return f.read()


def put_one_message(pubkey, db):
    enc_json = get_enc_json(pubkey, get_message())
    doc = get_new_doc(enc_json)
    db.put_doc(doc)


def put_lots_of_messages(db, number):
    log("Populating database with %d encrypted messages... "
        % number, line_break=False)
    pubkey = get_pubkey()

    def _put_one_message():
        put_one_message(pubkey, db)
    time = timeit.timeit(_put_one_message, number=number)
    log("done.")
    average_time = time / number
    log("put_one_message average time: %f" % average_time)
    return average_time
