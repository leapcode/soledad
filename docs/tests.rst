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
perform some actions. See the :ref:`documentation for benchmarks <benchmarks>`.
