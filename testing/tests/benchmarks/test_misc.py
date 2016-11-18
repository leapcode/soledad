import pytest

pytestmark = pytest.mark.benchmark


@pytest.mark.benchmark(group="test_instance")
def test_initialization(soledad_client, benchmark):
    benchmark(soledad_client)
