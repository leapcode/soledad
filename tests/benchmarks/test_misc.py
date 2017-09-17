import pytest


@pytest.mark.benchmark(group="test_instance")
def test_initialization(soledad_client, monitored_benchmark):
    """
    Soledad client object initialization.
    """
    monitored_benchmark(soledad_client)
