import sys
import os

from twisted.application import service, strports
from twisted.web import server
from twisted.python import log

from leap.soledad.server import entrypoints

application = service.Application('soledad-server')

# local entrypoint
local_port = os.getenv('LOCAL_SERVICES_PORT', 2525)
local_description = 'tcp:%s:interface=127.0.0.1' % local_port
local_site = server.Site(entrypoints.LocalServicesEntrypoint())

local_server = strports.service(local_description, local_site)
local_server.setServiceParent(application)

# public entrypoint
port = os.getenv('HTTPS_PORT', None)
if port == local_port:
    log.err("LOCAL_SERVICES_PORT and HTTPS_PORT can't be the same!")
    sys.exit(20)
if port:
    privateKey = os.getenv('PRIVKEY_PATH', '/etc/soledad/soledad-server.key')
    certKey = os.getenv('CERT_PATH', '/etc/soledad/soledad-server.pem')
    sslmethod = os.getenv('SSL_METHOD', 'SSLv23_METHOD')

    public_description = ':'.join([
        'ssl',
        'port=' + str(port),
        'privateKey=' + privateKey,
        'certKey=' + certKey,
        'sslmethod=' + sslmethod])
elif os.getenv('DEBUG_SERVER', False):
    public_description = 'tcp:port=2424:interface=0.0.0.0'
else:
    log.err("HTTPS_PORT env var is required to be set!")
    sys.exit(20)

public_site = server.Site(entrypoints.SoledadEntrypoint())

public_server = strports.service(public_description, public_site)
public_server.setServiceParent(application)
