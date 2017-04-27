import pytest


@pytest.mark.benchmark(group="test_instance")
def test_initialization(soledad_client, monitored_benchmark):
    monitored_benchmark(soledad_client)
