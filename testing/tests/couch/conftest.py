import couchdb
import pytest
import random
import string


@pytest.fixture
def random_name():
    return 'user-' + ''.join(
        random.choice(
            string.ascii_lowercase) for _ in range(10))


class RandomDatabase(object):

    def __init__(self, couch_url, name):
        self.couch_url = couch_url
        self.name = name
        self.server = couchdb.client.Server(couch_url)
        self.database = self.server.create(name)

    def teardown(self):
        self.server.delete(self.name)


@pytest.fixture
def db(random_name, request):
    couch_url = request.config.getoption('--couch-url')
    db = RandomDatabase(couch_url, random_name)
    request.addfinalizer(db.teardown)
    return db
