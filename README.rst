Soledad
==================================================================
*Synchronization Of Locally Encrypted Data Among Devices*

Soledad is the part of LEAP that allows application data to be
securely shared among devices. It provides, to other parts of the
LEAP project, an API for data storage and sync.

This software is under development.

From version ``0.9.7`` on, soledad is a single package, with extra dependencies
for the client and the server backends.

**leap.soledad**

.. image:: https://badge.fury.io/py/leap.soledad.common.svg
    :target: http://badge.fury.io/py/leap.soledad.common
.. image:: https://img.shields.io/pypi/dm/leap.soledad.common.svg
    :target: http://badge.fury.io/py/leap.soledad.common


Installing extra dependencies
-----------------------------

The client backend is based on sqlcipher::

  pip install ".[client]" 

The server depends on CouchDB::

  pip install ".[server]" 


Compatibility
-------------

* Soledad Server >= 0.7.0 is incompatible with client < 0.7.0 because of
  modifications on encrypted document MAC calculation.

* Soledad Server >= 0.7.0 is incompatible with LEAP Platform < 0.6.1 because
  that platform version implements ephemeral tokens databases and Soledad
  Server needs to act accordingly.

* Upgrades of Soledad Server < 0.9.0 to >= 0.9.0 need database migration
  because older code used to use CouchDB's design documents, while newer code
  got rid of that because it made everything cpu and memory hungry. See `the
  documentation
  <http://soledad.readthedocs.io/en/latest/migrations.html#soledad-server-0-8-to-0-9-couch-database-schema-migration-needed>`_
  for more information.


Tests
-----

Soledad's test suite depends on `tox <https://tox.readthedocs.io/en/latest/>`_,
which creates virtual environments and installs all needed dependencies to run
tests. Currently, some tests also depend on availability of a `CouchDB`_ server
(see :ref:`dependency-on-couchdb` for more information).

Once you have both *tox* and *CouchDB* installed in your system, just run the
``tox`` command in the root of the repository to get started running tests.

.. _dependency-on-couchdb:

---------------------
Dependency on CouchDB
---------------------

Currently, some tests depend on availability of a CouchDB server. This will
change in the future and only integration tests will depend on CouchDB.

By default, tests will try to access couch at ``http://127.0.0.1:5984/``. If
you have a CouchDB server running elsewhere, you can pass a custom url to
*pytest* by using the ``--couch-url`` option after two dashes (``--``) when
running tox::

  tox -- --couch-url http://couch_host:5984

Tests that depend on couchdb are marked as such with the ``needs_couch`` pytest
marker. You can skip them by avoiding tests with that marker::

  tox -- -m 'not needs_couch'

.. _`CouchDB`: https://couchdb.apache.org/

Privileges
----------
In order to prevent privilege escalation, Soledad should not be run as a
database administrator. This implies the following side effects:

-----------------
Database creation
-----------------

Can be done via a script located in ``pkg/server/soledad-create-userdb``
It reads a netrc file that should be placed on
``/etc/couchdb/couchdb-admin.netrc``.
That file holds the admin credentials in netrc format and should be accessible
only by 'soledad-admin' user.

The debian package will do the following in order to automate this:

* create a user ``soledad-admin``
* make this script available as ``soledad-create-userdb`` in ``/usr/bin``
* grant restricted sudo access, that only enables user ``soledad`` to call this
  exact command via ``soledad-admin`` user.

The server side process, configured via ``/etc/soledad/soledad-server.conf``, will
then use a parameter called 'create_cmd' to know which command is used to
allocate new databases. All steps of creation process is then handled
automatically by the server, following the same logic as u1db server.

-----------------
Database deletion
-----------------

No code at all handles this and privilege to do so needs to be removed as
explained before. This can be automated via a simple cron job.
