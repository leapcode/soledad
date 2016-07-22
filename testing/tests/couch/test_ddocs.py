from uuid import uuid4

from leap.soledad.common import couch

from test_soledad.util import CouchDBTestCase


class CouchDesignDocsTests(CouchDBTestCase):

    def setUp(self):
        CouchDBTestCase.setUp(self)

    def create_db(self, ensure=True, dbname=None):
        if not dbname:
            dbname = ('test-%s' % uuid4().hex)
        if dbname not in self.couch_server:
            self.couch_server.create(dbname)
        self.db = couch.CouchDatabase(
            (self.couch_url),
            dbname,
            ensure_ddocs=ensure)

    def tearDown(self):
        self.db.delete_database()
        self.db.close()
        CouchDBTestCase.tearDown(self)

    def test_ensure_security_doc(self):
        """
        Ensure_security creates a _security ddoc to ensure that only soledad
        will have the lowest privileged access to an user db.
        """
        self.create_db(ensure=False)
        self.assertFalse(self.db._database.resource.get_json('_security')[2])
        self.db.ensure_security_ddoc()
        security_ddoc = self.db._database.resource.get_json('_security')[2]
        self.assertIn('admins', security_ddoc)
        self.assertFalse(security_ddoc['admins']['names'])
        self.assertIn('members', security_ddoc)
        self.assertIn('soledad', security_ddoc['members']['names'])

    def test_ensure_security_from_configuration(self):
        """
        Given a configuration, follow it to create the security document
        """
        self.create_db(ensure=False)
        configuration = {'members': ['user1', 'user2'],
                         'members_roles': ['role1', 'role2'],
                         'admins': ['admin'],
                         'admins_roles': ['administrators']
                         }
        self.db.ensure_security_ddoc(configuration)

        security_ddoc = self.db._database.resource.get_json('_security')[2]
        self.assertEquals(configuration['admins'],
                          security_ddoc['admins']['names'])
        self.assertEquals(configuration['admins_roles'],
                          security_ddoc['admins']['roles'])
        self.assertEquals(configuration['members'],
                          security_ddoc['members']['names'])
        self.assertEquals(configuration['members_roles'],
                          security_ddoc['members']['roles'])
