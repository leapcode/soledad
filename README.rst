Soledad
==================================================================

*Synchronization Of Locally Encrypted Data Among Devices*

.. image:: https://badge.fury.io/py/leap.soledad.svg
    :target: http://badge.fury.io/py/leap.soledad

Soledad is the part of LEAP that allows application data to be
securely shared among devices. It provides, to other parts of the
LEAP project, an API for data storage and sync.

This software is under development.

Installing
----------

Soledad is distributed as a single package, with extra dependencies for the
client and the server backends. To install the main package from `pypi
<https://pypi.python.org/pypi/leap.soledad>`_, do the following::

    pip install leap.soledad

To use Soledad Client, make sure to install client-specific dependencies::

    pip install "leap.soledad[client]"

To use Soledad Server, also install server-specific dependencies::

    pip install "leap.soledad[server]"

If you want to install from the repository, you can do so like this::

    git clone https://0xacab.org/leap/soledad
    cd soledad/
    pip install .
    pip install ".[client]"
    pip install ".[server]"


Compatibility
-------------

See the documentation page about `compatibility
<http://soledad.readthedocs.io/en/latest/development/compatibility.html>`_
for information about compatibility between different versions of Soledad
Server and Client and with the LEAP Plaform.


Tests
-----

Soledad's test suite depends on `tox <https://tox.readthedocs.io/en/latest/>`_,
which creates virtual environments and installs all needed dependencies to run
tests. Currently, some tests also depend on availability of a `CouchDB`_ server
(see :ref:`dependency-on-couchdb` for more information).

Once you have both *tox* and *CouchDB* installed in your system, just run the
``tox`` command in the root of the repository to get started running tests.

See the `documentation pages about tests
<https://soledad.readthedocs.io/en/latest/development/tests.html>`_ for more details.

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
