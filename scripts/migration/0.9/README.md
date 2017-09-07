CouchDB schema migration script: from soledad-server < 0.9.0 to >= 0.9.0
========================================================================

Starting with Soledad Server 0.9.0, the CouchDB database schema was changed to
improve speed of the server side storage backend. Because of that, this script
has to be run for all Leap providers that used to provide email using Soledad
Server < 0.9.0.

If you never provided email with Leap, you don't need to run this script.


ATTENTION!
----------

  - This script does not backup your data for you. Make sure you have a backup
    copy of your databases before running this script!

  - Make sure you turn off any service that might be writing to the couch user
    databases before running this script. From the Leap side, these would be
    Leap MX in the "mx" node and Soledad Server in the "soledad" node.


Usage
-----

When you run the script, you will see no output. All the output will be logged
to files, as explained in the Log section below.

To see command line options, run:

    ./migrate.py --help

To see what the script would do, run the following and check the logs
afterwards:

    ./migrate.py

To actually run the migration, add the --do-migrate command line option:

    ./migrate.py --do-migrate


Log
---

The script will be installed in ``/usr/share/soledad-server/migration/0.9``,
and will log the results of any run by default to the ``logs/`` subdirectory of
that folder (i.e. ``/usr/share/soledad-server/migration/0.9/logs``).

If you don't pass a ``--log-file`` command line option, a log will be written
to the log folder as described above.


Differences between old and new couch schema
--------------------------------------------

The differences between old and new schemas are:

    - Transaction metadata was previously stored inside each document, and we
      used design doc view/list functions to retrieve that information. Now,
      transaction metadata is stored in documents with special ids
      (gen-0000000001 to gen-9999999999).

    - Database replica config metadata was stored in a document called
      "u1db_config", and now we store it in the "_local/config" document.

    - Sync metadata was previously stored in documents with id
      "u1db_sync_<source-replica-id>", and now are stored in
      "_local/sync_<source-replica-id>".

    - The new schema doesn't make use of any design documents.


What does this script do
------------------------

- List all databases starting with "user-".
- For each one, do:
  - Check if it contains the old "u1db_config" document.
  - If it doesn't, skip this db.
  - Get the transaction log using the usual design doc view/list functions.
  - Write a new "gen-X" document for each line on the transaction log.
  - Get the "u1db_config" document, create a new one in "_local/config",
    Delete the old one.
  - List all "u1db_sync_X" documents, create new ones in "_local/sync_X",
    delete the old ones.
  - Delete unused design documents.
