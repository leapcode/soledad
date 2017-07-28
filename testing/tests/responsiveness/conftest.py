import pytest

import elastic
import watchdog as wd


def _post_results(dog, request):
    elastic.post(dog.seconds_blocked, request)


@pytest.fixture
def watchdog(request):
    dog = wd.Watchdog()
    dog_d = dog.start()
    request.addfinalizer(lambda: _post_results(dog, request))

    def _run(deferred_fun):
        deferred_fun().addCallback(lambda _: dog.stop())
        return dog_d
    return _run


def pytest_configure(config):
    option = config.getoption("elasticsearch_url", elastic.ELASTICSEARCH_URL)
    elastic.ELASTICSEARCH_URL = option
