#!/usr/bin/python

# This script gives server-side access to one Soledad user database by using
# the configuration stored in /etc/leap/soledad-server.conf.
#
# Use it like this:
# 
#     python -i server-side-db.py <uuid>

import sys
from ConfigParser import ConfigParser

from leap.soledad.common.couch import CouchDatabase

if len(sys.argv) != 2:
    print 'Usage: %s <uuid>' % sys.argv[0]
    exit(1)

uuid = sys.argv[1]

# get couch url
cp = ConfigParser()
cp.read('/etc/leap/soledad-server.conf')
url = cp.get('soledad-server', 'couch_url')

# access user db
dbname = 'user-%s' % uuid
db = CouchDatabase(url, dbname)

# get replica info
replica_uid = db._replica_uid
gen, docs = db.get_all_docs()
print "dbname:      %s" % dbname
print "replica_uid: %s" % replica_uid
print "generation:  %d" % gen

# get relevant docs
schemes = map(lambda d: d.content['_enc_scheme'], docs)
pubenc = filter(lambda d: d.content['_enc_scheme'] == 'pubkey', docs)

print "total number of docs:  %d" % len(docs)
print "pubkey encrypted docs: %d" % len(pubenc)
