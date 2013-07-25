Soledad 
==================================================================
*Synchronization Of Locally Encrypted Data Among Devices*

.. image:: https://pypip.in/v/leap.soledad/badge.png
        :target: https://crate.io/packages/leap.soledad

This software is under development.

Tests
-----

Client and server tests are both included in leap.soledad. Because
soledad_server depends on soledad and soledad tests depend on soledad_server,
if you want to run tests in development mode you must first install soledad,
then soledad_server, and then run the tests.

Therefore, tests must be run with::

  cd soledad
  python setup.py develop
  cd ../soledad_server
  python setup.py develop
  cd ../soledad
  python setup.py test

Note that to run CouchDB tests, be sure you have ``CouchDB`` installed on your
system.
