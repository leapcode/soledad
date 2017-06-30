Tests
=====

We use `pytest <https://docs.pytest.org/en/latest/>`_ as a testing framework
and `Tox <https://tox.readthedocs.io>`_ as a test environment manager.
Currently, tests reside in the  `testing/` folder and some of them need a
couchdb server to be run against.

If you do have a couchdb server running on localhost on default port, the
following command should be enough to run tests::

    cd testing
    tox

CouchDB dependency
------------------

In case you want to use a couchdb on another host or port, use the
`--couch-url` parameter for `pytest`::

    cd testing
    tox -- --couch-url=http://couch_host:5984

If you want to exclude all tests that depend on couchdb, deselect tests marked
with `needs_couch`::

    cd testing
    tox -- -m 'not needs_couch'

Benchmark tests
---------------

A set of benchmark tests is provided to measure the time and resources taken to
perform some actions.

`pytest-benchmark` runs tests multiple times so it can provide meaningful
statistics for the time taken for a tipical run of a test function. The number
of times that the test is run can be manually or automatically configured. When
automatically configured, the number of runs is decided by taking into account
multiple `pytest-benchmark` configuration parameters. See the `the
corresponding documenation
<https://pytest-benchmark.readthedocs.io/en/stable/calibration.html>`_ for more
details on how automatic calibration works.

The actual number of times a test is run depends on many parameters: the time
taken for a sample run and the configuration of the minimum number of rounds
and maximum time allowed for a benchmark. For a snapshot of the number of
rounds for each test function see `the soledad benchmarks wiki page
<https://0xacab.org/leap/soledad/wikis/benchmarks>`_.

Some graphs and analysis resulting from these tests can be seen on `the
benchmarks page <https://benchmarks.leap.se/>`_.
