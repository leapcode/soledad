from u1db.remote import (
    http_database,
)

from leap.soledad.client import (
    auth,
    VerifiedHTTPSConnection,
)
from leap.soledad.common.document import SoledadDocument
from leap.soledad.server import SoledadApp
from leap.soledad.server.auth import SoledadTokenAuthMiddleware


from leap.soledad.common.tests import u1db_tests as tests
from leap.soledad.common.tests import BaseSoledadTest
from leap.soledad.common.tests.u1db_tests import test_backends


#-----------------------------------------------------------------------------
# The following tests come from `u1db.tests.test_backends`.
#-----------------------------------------------------------------------------

def make_leap_document_for_test(test, doc_id, rev, content,
                                has_conflicts=False):
    return SoledadDocument(
        doc_id, rev, content, has_conflicts=has_conflicts)


def make_soledad_app(state):
    return SoledadApp(state)


def make_token_soledad_app(state):
    app = SoledadApp(state)

    def _verify_authentication_data(uuid, auth_data):
        if uuid == 'user-uuid' and auth_data == 'auth-token':
            return True
        return False

    # we test for action authorization in leap.soledad.common.tests.test_server
    def _verify_authorization(uuid, environ):
        return True

    application = SoledadTokenAuthMiddleware(app)
    application._verify_authentication_data = _verify_authentication_data
    application._verify_authorization = _verify_authorization
    return application


LEAP_SCENARIOS = [
    ('http', {
        'make_database_for_test': test_backends.make_http_database_for_test,
        'copy_database_for_test': test_backends.copy_http_database_for_test,
        'make_document_for_test': make_leap_document_for_test,
        'make_app_with_state': make_soledad_app}),
]


def make_token_http_database_for_test(test, replica_uid):
    test.startServer()
    test.request_state._create_database(replica_uid)

    class _HTTPDatabaseWithToken(
            http_database.HTTPDatabase, auth.TokenBasedAuth):

        def set_token_credentials(self, uuid, token):
            auth.TokenBasedAuth.set_token_credentials(self, uuid, token)

        def _sign_request(self, method, url_query, params):
            return auth.TokenBasedAuth._sign_request(
                self, method, url_query, params)

    http_db = _HTTPDatabaseWithToken(test.getURL('test'))
    http_db.set_token_credentials('user-uuid', 'auth-token')
    return http_db


def copy_token_http_database_for_test(test, db):
    # DO NOT COPY OR REUSE THIS CODE OUTSIDE TESTS: COPYING U1DB DATABASES IS
    # THE WRONG THING TO DO, THE ONLY REASON WE DO SO HERE IS TO TEST THAT WE
    # CORRECTLY DETECT IT HAPPENING SO THAT WE CAN RAISE ERRORS RATHER THAN
    # CORRUPT USER DATA. USE SYNC INSTEAD, OR WE WILL SEND NINJA TO YOUR
    # HOUSE.
    http_db = test.request_state._copy_database(db)
    http_db.set_token_credentials(http_db, 'user-uuid', 'auth-token')
    return http_db


class SoledadTests(test_backends.AllDatabaseTests, BaseSoledadTest):

    scenarios = LEAP_SCENARIOS + [
        ('token_http', {'make_database_for_test':
                        make_token_http_database_for_test,
                        'copy_database_for_test':
                        copy_token_http_database_for_test,
                        'make_document_for_test': make_leap_document_for_test,
                        'make_app_with_state': make_token_soledad_app,
                        })
    ]

load_tests = tests.load_with_scenarios
