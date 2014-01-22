#!/usr/bin/python

# This script gives client-side access to one Soledad user database by using
# the data stored in the appropriate config dir given by get_path_prefix().
#
# Use it like this:
#
#     python -i client-side-db.py <uuid> <passphrase>

import sys
import os

from leap.common.config import get_path_prefix
from leap.soledad.client import Soledad

if len(sys.argv) != 3:
    print 'Usage: %s <uuid> <passphrase>' % sys.argv[0]
    exit(1)

uuid = sys.argv[1]
passphrase = unicode(sys.argv[2])

secrets_path = os.path.join(get_path_prefix(), 'leap', 'soledad',
                            '%s.secret' % uuid)
local_db_path = os.path.join(get_path_prefix(), 'leap', 'soledad',
                             '%s.db' % uuid)
server_url = 'http://dummy-url'
cert_file = 'cert'

sol = Soledad(uuid, passphrase, secrets_path, local_db_path, server_url,
             cert_file)
db = sol._db

# get replica info
replica_uid = db._replica_uid
gen, docs = db.get_all_docs()
print "replica_uid: %s" % replica_uid
print "generation:  %d" % gen
gen, trans_id = db._get_generation_info()
print "transaction_id: %s" % trans_id
