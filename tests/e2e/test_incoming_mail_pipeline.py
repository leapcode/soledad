# This script does the following:
#
# - create a user using bonafide and and invite code given as an environment
#   variable.
#
# - create and upload an OpenPGP key manually, as that would be
#   a responsibility of bitmask-dev.
#
# - send an email to the user using sendmail, with a secret in the body.
#
# - start a soledad client using the created user.
#
# - download pending blobs. There should be only one.
#
# - look inside the blob, parse the email message.
#
# - compare the token in the incoming message with the token in the sent
#   message and succeed if the tokens are the same.
#
# - delete the user (even if the test failed). (TODO)


import pytest

from utils import get_session
from utils import gen_key
from utils import put_key
from utils import send_email
from utils import get_incoming_fd
from utils import get_received_secret


@pytest.inlineCallbacks
def test_incoming_mail_pipeline(soledad_client, tmpdir):

    # create a user and login
    session = yield get_session(tmpdir)

    # create a OpenPGP key and upload it
    key = gen_key(session.username)
    yield put_key(session.uuid, session.token, str(key.pubkey))

    # get a soledad client for that user
    client = soledad_client(
        uuid=session.uuid,
        passphrase='123',
        token=session.token)

    # send the email
    sent_secret = send_email(session.username)

    # check the incoming blob and compare sent and received secrets
    fd = yield get_incoming_fd(client)
    received_secret = get_received_secret(key, fd)
    assert sent_secret == received_secret
    # TODO: delete user in the end
