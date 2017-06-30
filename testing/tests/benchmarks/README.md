Benchmark tests
===============

This folder contains benchmark tests for Soledad. It aims to provide a fair
account on the time and resources taken to perform some actions.

These benchmarks are built on top of `pytest-benchmark`, a `pytest` fixture that
provides means for running test functions multiple times and generating
reports. The results are printed to screen and also posted to elasticsearch.

`pytest-benchmark` runs tests multiple times so it can provide meaningful
statistics for the time taken for a tipical run of a test function. The number
of times that the test is run can be manually or automatically configured. When
automatically configured, the number of runs is decided by taking into account
multiple `pytest-benchmark` configuration parameters. See the following page
for more details on how `pytest-benchmark` works:

  https://pytest-benchmark.readthedocs.io/en/stable/calibration.html

Some graphs and analysis resulting from these tests can be seen on:

  https://benchmarks.leap.se/


Resource consumption
--------------------

For each test, CPU and memory usage statistics are also collected, by querying
`cpu_percent()` and `memory_percent()` from `psutil.Process` for the current
test process. Some notes about the current resource consumption estimation process:

* Currently, resources are measured for the whole set of rounds that a test
  function is run. That means that the CPU and memory percentage include the
  `pytest` and `pytest-benchmark` machinery overhead. Anyway, for now this might
  provide a fair approximation of per-run test function resource usage.

* CPU is measured before and after the run of the benchmark function and
  returns the percentage that the currnet process occupied of the CPU time
  between the two calls.

* Memory is sampled during the benchmark run by a separate thread. Sampling
  interval might have to be configured on a per-test basis, as different tests
  take different times to execute (from milliseconds to tens of seconds). For
  now, an interval of 0.1s seems to cover all tests.
