.. _soledad-server:

Soledad Server
==============

Soledad Server is a document store and a blobs server that can synchronize data
with a Soledad Client.

.. _server-config-file:

Configuring
-----------

Soledad Server looks for a configuration file in
``/etc/soledad/soledad-server.conf`` and will read the following configuration
options from the ``[soledad-server]`` section:

====================== =============================================== ================================
Option                 Description                                     Default value
====================== =============================================== ================================
couch_url              The URL of the CouchDB backend storage.         ``http://localhost:5984``
create_cmd             The shell command to create user databases.     None
admin_netrc            The netrc file to be used for authenticating    ``/etc/couchdb/couchdb.netrc``
                       with the CouchDB backend storage.
batching               Whether to use batching capabilities for        ``true``
                       synchronization.
blobs                  Whether to provide the Blobs functionality or   ``false``
                       not.
blobs_path             The path for blobs storage in the server's file ``/var/lib/soledad/blobs``
                       system.
concurrent_blob_writes Limit of concurrent blob writes to the          50
                       filesystem.
services_tokens_file   The file containing authentication tokens for   ``/etc/soledad/services.tokens``
                       services provided through the Services API.
====================== =============================================== ================================

Running
-------

This is written as a Twisted application and intended to be run using the
twistd command. To start the soledad server, run:

.. code-block:: bash

    twistd -n --python /path/to/leap/soledad/server/server.tac

An systemd script is included in the `Debian packages
<http://deb.leap.se/repository/>`_ to make it feasible to start and stop the
Soledad server service using a standard interface.

Migrations
----------

Some updates of Soledad need manual intervention for database migration because
of changes to the storage backend. In all such cases, we will document the
steps needed for migration in this page.

Soledad Server 0.8 to 0.9 - Couch Database schema migration needed
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Starting with Soledad Server 0.9.0, the CouchDB database schema was changed to
improve speed of the server side storage backend. Because of that, this script
has to be run for all Leap providers that used to provide email using Soledad
Server < 0.9.0.

The migration script can be found:

* In `the Soledad repository <https://0xacab.org/leap/soledad/tree/master/scripts/migration/0.9>`_.
* In ``/usr/share/soledad-server/migration/0.9/`` when the ``soledad-server`` debian package is installed.

Instructions for migration can be found in the ``README.md`` file. Make sure to read it carefully and backup your data before starting the migration process.

