.. _benchmarks:

Benchmarks
==========

We currently use `pytest-benchmark <https://pytest-benchmark.readthedocs.io/>`_
to write tests to assess the time and resources taken by various tasks.

Results of benchmarking can be seen in https://benchmarks.leap.se/.

Test repetition
---------------

``pytest-benchmark`` runs tests multiple times so it can provide meaningful
statistics for the time taken for a tipical run of a test function. The number
of times that the test is run can be manually or automatically configured.

When automatically configured, the number of runs is decided by taking into
account multiple ``pytest-benchmark`` configuration parameters. See the `the
corresponding documenation
<https://pytest-benchmark.readthedocs.io/en/stable/calibration.html>`_ for more
details on how automatic calibration works.

To achieve a reasonable number of repetitions and a reasonable amount of time
at the same time, we let ``pytest-benchmark`` choose the number of repetitions
for faster tests, and manually limit the number of repetitions for slower tests.

Currently, tests for `synchronization` and `sqlcipher asynchronous document
creation` are fixed to run 4 times each. All the other tests are left for
``pytest-benchmark`` to decide how many times to run each one. With this setup,
the benchmark suite is taking approximatelly 7 minutes to run in our CI server.
As the benchmark suite is run twice (once for time and cpu stats and a second
time for memory stats), the whole benchmarks run takes around 15 minutes.

The actual number of times a test is run when calibration is done automatically
by ``pytest-benchmark`` depends on many parameters: the time taken for a sample
run and the configuration of the minimum number of rounds and maximum time
allowed for a benchmark. For a snapshot of the number of rounds for each test
function see `the soledad benchmarks wiki page
<https://0xacab.org/leap/soledad/wikis/benchmarks>`_.

Sync size statistics
--------------------

Currenly, the main use of Soledad is to synchronize client-encrypted email
data. Because of that, it makes sense to measure the time and resources taken
to synchronize an amount of data that is realistically comparable to a user's
email box.

In order to determine what is a good example of dataset for synchronization
tests, we used the size of messages of one week of incoming and outgoing email
flow of a friendly provider. The statistics that came out from that are (all
sizes are in KB):

+--------+-----------+-----------+
|        | outgoing  | incoming  |
+========+===========+===========+
| min    | 0.675     | 0.461     |
+--------+-----------+-----------+
| max    | 25531.361 | 25571.748 |
+--------+-----------+-----------+
| mean   | 252.411   | 110.626   |
+--------+-----------+-----------+
| median | 5.320     | 14.974    |
+--------+-----------+-----------+
| mode   | 1.404     | 1.411     |
+--------+-----------+-----------+
| stddev | 1376.930  | 732.933   |
+--------+-----------+-----------+

Test scenarios
--------------

Ideally, we would want to run tests for a big data set, but that may be
infeasible given time and resource limitations. Because of that, we choose a
smaller data set and suppose that the behaviour is somewhat linear to get an
idea for larger sets.

Supposing a data set size of 10MB, some possibilities for number of documents
and document sizes for testing download and upload are:

* 10 x 1M
* 20 x 500K
* 100 x 100K
* 200 x 50K
* 1000 x 10K

The above scenarios all have documents of the same size. If we want to account
for some variability on document sizes, it is sufficient to come up with a
simple scenario where the average, minimum and maximum sizes are somehow
coherent with the above statistics, like the following one:

* 60 x 15KB + 1 x 1MB
