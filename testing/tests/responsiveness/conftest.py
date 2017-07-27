import pytest

from watchdog import Watchdog


def _post_results(dog):
    print("\n")
    print("+" * 50)
    print(dog.seconds_blocked)
    print("+" * 50)


@pytest.fixture
def watchdog(request):
    dog = Watchdog()
    dog_d = dog.start()
    request.addfinalizer(lambda: _post_results(dog))

    def _run(deferred_fun):
        deferred_fun().addCallback(lambda _: dog.stop())
        return dog_d
    return _run
