import pytest


@pytest.mark.benchmark(group="test_instance")
def test_instance(soledad_client, benchmark):
    benchmark(soledad_client)
