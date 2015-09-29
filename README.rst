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

.. image:: https://badge.fury.io/py/leap.soledad.common.svg
    :target: http://badge.fury.io/py/leap.soledad.common
.. image:: https://img.shields.io/pypi/dm/leap.soledad.common.svg
    :target: http://badge.fury.io/py/leap.soledad.common

**leap.soledad.client** where the soledad client lives.

.. image:: https://badge.fury.io/py/leap.soledad.client.svg
    :target: http://badge.fury.io/py/leap.soledad.client
.. image:: https://img.shields.io/pypi/dm/leap.soledad.client.svg
    :target: http://badge.fury.io/py/leap.soledad.client

**leap.soledad.server** oh surprise! bits needed for the soledad server.

.. image:: https://badge.fury.io/py/leap.soledad.server.svg
    :target: http://badge.fury.io/py/leap.soledad.server
.. image:: https://img.shields.io/pypi/dm/leap.soledad.server.svg
    :target: http://badge.fury.io/py/leap.soledad.server


Compatibility
-------------

* Soledad Server >= 0.7.0 is incompatible with client < 0.7.0 because of
  modifications on encrypted document MAC calculation.

* Soledad Server >= 0.7.0 is incompatible with LEAP Platform < 0.6.1 because
  that platform version implements ephemeral tokens databases and Soledad
  Server needs to act accordingly.


Tests
-----

Client and server tests are both included in leap.soledad.common. If you want
to run tests in development mode you must do the following::

  scripts/develop_mode.sh
  ./run_tests.sh

Note that to run CouchDB tests, be sure you have [CouchDB](https://couchdb.apache.org/) installed on your
system.


Privileges
-----
In order to prevent privilege escalation, Soledad should not be run as a
database administrator. This implies the following side effects:

-----------------
Database creation:
-----------------
Can be done via a script located in ``server/pkg/create-user-db``
It reads a netrc file that should be placed on
``/etc/couchdb/couchdb-admin.netrc``.
That file holds the admin credentials in netrc format and should be accessible
only by 'soledad-admin' user.

The debian package will do the following in order to automate this:

* create a user ``soledad-admin``
* make this script available as ``create-user-db`` in ``/usr/bin``
* grant restricted sudo access, that only enables user ``soledad`` to call this
  exact command via ``soledad-admin`` user.

The server side process, configured via ``/etc/leap/soledad-server.conf``, will
then use a parameter called 'create_cmd' to know which command is used to
allocate new databases. All steps of creation process is then handled
automatically by the server, following the same logic as u1db server.

------------------
Database deletion:
------------------
No code at all handles this and privilege to do so needs to be removed as
explained before. This can be automated via a simple cron job.
