import os

from twisted.application import service, strports
from twisted.web import server

from leap.soledad.server import entrypoint

application = service.Application('soledad-server')

# local entrypoint
local_description = 'tcp:2323:interface=127.0.0.1'
local_site = server.Site(entrypoint.LocalServicesEntrypoint())

local_server = strports.service(local_description, local_site)
local_server.setServiceParent(application)

# public entrypoint
port = os.getenv('HTTPS_PORT', None)
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
else:
    public_description = 'tcp:port=2424:interface=0.0.0.0'
public_site = server.Site(entrypoint.SoledadEntrypoint())

public_server = strports.service(public_description, public_site)
public_server.setServiceParent(application)
