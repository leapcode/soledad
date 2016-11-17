import hashlib
import couchdb

from leap.soledad.common.couch import CouchDatabase

from util import log
from couchdb_wrapper import CouchDBWrapper


def start_couchdb_wrapper():
    log("Starting couchdb... ", line_break=False)
    couchdb_wrapper = CouchDBWrapper()
    couchdb_wrapper.start()
    log("couchdb started on port %d." % couchdb_wrapper.port)
    return couchdb_wrapper


def get_u1db_database(dbname, port):
    return CouchDatabase.open_database(
        'http://127.0.0.1:%d/%s' % (port, dbname),
        True)


def create_tokens_database(port, uuid, token_value):
    tokens_database = couchdb.Server(
        'http://127.0.0.1:%d' % port).create('tokens')
    token = couchdb.Document()
    token['_id'] = hashlib.sha512(token_value).hexdigest()
    token['user_id'] = uuid
    token['type'] = 'Token'
    tokens_database.save(token)


def get_couchdb_wrapper_and_u1db(uuid, token_value):
    couchdb_wrapper = start_couchdb_wrapper()

    couchdb_u1db = get_u1db_database('user-%s' % uuid, couchdb_wrapper.port)
    get_u1db_database('shared', couchdb_wrapper.port)
    create_tokens_database(couchdb_wrapper.port, uuid, token_value)

    return couchdb_wrapper, couchdb_u1db
