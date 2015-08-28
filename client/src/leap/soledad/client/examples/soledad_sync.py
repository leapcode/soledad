from leap.bitmask.config.providerconfig import ProviderConfig
from leap.bitmask.crypto.srpauth import SRPAuth
from leap.soledad.client import Soledad
from twisted.internet import reactor
import logging
logging.basicConfig(level=logging.DEBUG)


# EDIT THIS --------------------------------------------
user = u"USERNAME"
uuid = u"USERUUID"
_pass = u"USERPASS"
server_url = "https://soledad.server.example.org:2323"
# EDIT THIS --------------------------------------------

secrets_path = "/tmp/%s.secrets" % uuid
local_db_path = "/tmp/%s.soledad" % uuid
cert_file = "/tmp/cacert.pem"
provider_config = '/tmp/cdev.json'


provider = ProviderConfig()
provider.load(provider_config)

soledad = None


def printStuff(r):
    print r


def printErr(err):
    logging.exception(err.value)


def init_soledad(_):
    token = srpauth.get_token()
    print "token", token

    global soledad
    soledad = Soledad(uuid, _pass, secrets_path, local_db_path,
                      server_url, cert_file,
                      auth_token=token, defer_encryption=False)

    def getall(_):
        d = soledad.get_all_docs()
        return d

    d1 = soledad.create_doc({"test": 42})
    d1.addCallback(getall)
    d1.addCallbacks(printStuff, printErr)

    d2 = soledad.sync()
    d2.addCallbacks(printStuff, printErr)
    d2.addBoth(lambda r: reactor.stop())


srpauth = SRPAuth(provider)

d = srpauth.authenticate(user, _pass)
d.addCallbacks(init_soledad, printErr)

reactor.run()
