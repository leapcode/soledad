Soledad 
==================================================================
*Synchronization Of Locally Encrypted Data Among Devices*

.. image:: https://pypip.in/v/leap.soledad/badge.png
        :target: https://crate.io/packages/leap.soledad

This software is under development.

Tests
-----

Client and server tests are both included in leap.soledad.common. If you want
to run tests in development mode you must do the following::

  cd common
  python setup.py develop
  cd ../client
  python setup.py develop
  cd ../server
  python setup.py develop
  cd ../common
  python setup.py test

Note that to run CouchDB tests, be sure you have ``CouchDB`` installed on your
system.
