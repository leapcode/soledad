import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--couch-url", type="string", default="http://127.0.0.1:5984",
        help="the url for the couch server to be used during tests")


@pytest.fixture
def couch_url(request):
    url = request.config.getoption('--couch-url')
    request.cls.couch_url = url


@pytest.fixture
def method_tmpdir(request, tmpdir):
    request.instance.tempdir = tmpdir.strpath
