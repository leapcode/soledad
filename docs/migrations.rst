Migrations
==========

Some updates of Soledad need manual intervention for database migration because
of changes to the storage backend. In all such cases, we will document the
steps needed for migration in this page.

Soledad Server 0.8 to 0.9 - Couch Database schema migration needed
------------------------------------------------------------------

Starting with Soledad Server 0.9.0, the CouchDB database schema was changed to
improve speed of the server side storage backend. Because of that, this script
has to be run for all Leap providers that used to provide email using Soledad
Server < 0.9.0.

The migration script can be found:

* In `the Soledad repository <https://0xacab.org/leap/soledad/tree/master/scripts/migration/0.8-to-0.9>`_.
* In ``/usr/share/soledad-server/migration/0.8-to-0.9/`` when the ``soledad-server`` debian package is installed.

Instructions for migration can be found in the ``README.md`` file. Make sure to read it carefully and backup your data before starting the migration process.

