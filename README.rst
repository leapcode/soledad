Soledad 
==================================================================
*Synchronization Of Locally Encrypted Data Among Devices*

Soledad is the part of LEAP that allows application data to be
securely shared among devices. It provides, to other parts of the 
LEAP project, an API for data storage and sync.

This software is under development.

There are currently three python packages maintained under this
repository:

**leap.soledad.common** common pieces.

.. image:: https://pypip.in/v/leap.soledad.common/badge.png
        :target: https://crate.io/packages/leap.soledad.common

**leap.soledad.client** where the soledad client lives.

.. image:: https://pypip.in/v/leap.soledad.client/badge.png
        :target: https://crate.io/packages/leap.soledad.client

**leap.soledad.server** oh surprise! bits needed for the soledad server.

.. image:: https://pypip.in/v/leap.soledad.server/badge.png
        :target: https://crate.io/packages/leap.soledad.server


Tests
-----

Client and server tests are both included in leap.soledad.common. If you want
to run tests in development mode you must do the following::

  scripts/develop_mode.sh
  ./run_tests.sh

Note that to run CouchDB tests, be sure you have ``CouchDB`` installed on your
system.
