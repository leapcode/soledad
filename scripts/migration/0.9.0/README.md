CouchDB schema migration to Soledad 0.8.2
=========================================

Migrate couch database schema from <= 0.8.1 version to 0.8.2 version.


ATTENTION!
----------

  - This script does not backup your data for you. Make sure you have a backup
    copy of your databases before running this script!

  - Make sure you turn off any service that might be writing to the couch
    database before running this script.


Usage
-----

To see what the script would do, run:

    ./migrate.py

To actually run the migration, add the --do-migrate command line option:

    ./migrate.py --do-migrate

See command line options:

    ./migrate.py --help


Log
---

If you don't pass a --log-file command line option, a log will be written to
the `log/` folder.


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
