from uuid import uuid4

from leap.soledad.common.couch import errors
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
            ('http://127.0.0.1:%d' % self.couch_port),
            dbname,
            ensure_ddocs=ensure)

    def tearDown(self):
        self.db.delete_database()
        self.db.close()
        CouchDBTestCase.tearDown(self)

    def test_missing_design_doc_raises(self):
        """
        Test that all methods that access design documents will raise if the
        design docs are not present.
        """
        self.create_db(ensure=False)
        # get_generation_info()
        self.assertRaises(
            errors.MissingDesignDocError,
            self.db.get_generation_info)
        # get_trans_id_for_gen()
        self.assertRaises(
            errors.MissingDesignDocError,
            self.db.get_trans_id_for_gen, 1)
        # get_transaction_log()
        self.assertRaises(
            errors.MissingDesignDocError,
            self.db.get_transaction_log)
        # whats_changed()
        self.assertRaises(
            errors.MissingDesignDocError,
            self.db.whats_changed)

    def test_missing_design_doc_functions_raises(self):
        """
        Test that all methods that access design documents list functions
        will raise if the functions are not present.
        """
        self.create_db(ensure=True)
        # erase views from _design/transactions
        transactions = self.db._database['_design/transactions']
        transactions['lists'] = {}
        self.db._database.save(transactions)
        # get_generation_info()
        self.assertRaises(
            errors.MissingDesignDocListFunctionError,
            self.db.get_generation_info)
        # get_trans_id_for_gen()
        self.assertRaises(
            errors.MissingDesignDocListFunctionError,
            self.db.get_trans_id_for_gen, 1)
        # whats_changed()
        self.assertRaises(
            errors.MissingDesignDocListFunctionError,
            self.db.whats_changed)

    def test_absent_design_doc_functions_raises(self):
        """
        Test that all methods that access design documents list functions
        will raise if the functions are not present.
        """
        self.create_db(ensure=True)
        # erase views from _design/transactions
        transactions = self.db._database['_design/transactions']
        del transactions['lists']
        self.db._database.save(transactions)
        # get_generation_info()
        self.assertRaises(
            errors.MissingDesignDocListFunctionError,
            self.db.get_generation_info)
        # _get_trans_id_for_gen()
        self.assertRaises(
            errors.MissingDesignDocListFunctionError,
            self.db.get_trans_id_for_gen, 1)
        # whats_changed()
        self.assertRaises(
            errors.MissingDesignDocListFunctionError,
            self.db.whats_changed)

    def test_missing_design_doc_named_views_raises(self):
        """
        Test that all methods that access design documents' named views  will
        raise if the views are not present.
        """
        self.create_db(ensure=True)
        # erase views from _design/docs
        docs = self.db._database['_design/docs']
        del docs['views']
        self.db._database.save(docs)
        # erase views from _design/syncs
        syncs = self.db._database['_design/syncs']
        del syncs['views']
        self.db._database.save(syncs)
        # erase views from _design/transactions
        transactions = self.db._database['_design/transactions']
        del transactions['views']
        self.db._database.save(transactions)
        # get_generation_info()
        self.assertRaises(
            errors.MissingDesignDocNamedViewError,
            self.db.get_generation_info)
        # _get_trans_id_for_gen()
        self.assertRaises(
            errors.MissingDesignDocNamedViewError,
            self.db.get_trans_id_for_gen, 1)
        # _get_transaction_log()
        self.assertRaises(
            errors.MissingDesignDocNamedViewError,
            self.db.get_transaction_log)
        # whats_changed()
        self.assertRaises(
            errors.MissingDesignDocNamedViewError,
            self.db.whats_changed)

    def test_deleted_design_doc_raises(self):
        """
        Test that all methods that access design documents will raise if the
        design docs are not present.
        """
        self.create_db(ensure=True)
        # delete _design/docs
        del self.db._database['_design/docs']
        # delete _design/syncs
        del self.db._database['_design/syncs']
        # delete _design/transactions
        del self.db._database['_design/transactions']
        # get_generation_info()
        self.assertRaises(
            errors.MissingDesignDocDeletedError,
            self.db.get_generation_info)
        # get_trans_id_for_gen()
        self.assertRaises(
            errors.MissingDesignDocDeletedError,
            self.db.get_trans_id_for_gen, 1)
        # get_transaction_log()
        self.assertRaises(
            errors.MissingDesignDocDeletedError,
            self.db.get_transaction_log)
        # whats_changed()
        self.assertRaises(
            errors.MissingDesignDocDeletedError,
            self.db.whats_changed)

    def test_ensure_ddoc_independently(self):
        """
        Test that a missing ddocs other than _design/docs will be ensured
        even if _design/docs is there.
        """
        self.create_db(ensure=True)
        del self.db._database['_design/transactions']
        self.assertRaises(
            errors.MissingDesignDocDeletedError,
            self.db.get_transaction_log)
        self.create_db(ensure=True, dbname=self.db._dbname)
        self.db.get_transaction_log()

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
