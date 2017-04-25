import pytest
import random
import time

from decimal import Decimal


def bellardBig(n):
    # http://en.wikipedia.org/wiki/Bellard%27s_formula
    pi = Decimal(0)
    k = 0
    while k < n:
        pi += (Decimal(-1) ** k / (1024 ** k)) * (
            Decimal(256) / (10 * k + 1) +
            Decimal(1) / (10 * k + 9) -
            Decimal(64) / (10 * k + 3) -
            Decimal(32) / (4 * k + 1) -
            Decimal(4) / (10 * k + 5) -
            Decimal(4) / (10 * k + 7) -
            Decimal(1) / (4 * k + 3))
        k += 1
    pi = pi * 1 / (2 ** 6)
    return pi


def test_long_operation(monitored_benchmark):

    def _long_operation():
        sleep = [random.uniform(0.5, 1.5) for _ in xrange(3)]
        while sleep:
            t = sleep.pop()
            time.sleep(t)
            bellardBig(int((10 ** 3) * t))

    results = monitored_benchmark(_long_operation)
    print results
