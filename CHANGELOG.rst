0.9.0 - 11 November, 2016
+++++++++++++++++++++++++

Main features
~~~~~~~~~~~~~

- Server-side changes in couch backend schema.
- Use of tox and pytest to run tests.
- Performance tests.

Server
======

*** Attention: Migration needed! ***

This version of soledad uses a different database schema in the server couch
backend. The difference from the old schema is that the use of design documents
for storing and accessing soledad db metadata was removed because incurred in
too much memory and time overhead for passing data to the javascript
interpreter.

Because of that, you need to run a migration script on your database. Check the
`scripts/migration/0.9.0/` diretctory for instructions on how to run the
migration script on your database. Don't forget to backup before running the
script!

Bugfixes
~~~~~~~~
- Fix order of multipart serialization when writing to couch.

Features
~~~~~~~~
- Log to syslog.
- Remove usage of design documents in couch backend.
- Use _local couch docs for metadata storage.
- Other small improvements in couch backend.


0.8.1 - 14 July, 2016
+++++++++++++++++++++

Client
======

Features
~~~~~~~~
- Add recovery document format version for future migrations.
- Use DeferredLock instead of its locking cousin.
- Use DeferredSemaphore instead of its locking cousin.

Bugfixes
~~~~~~~~
- `#8180 <https://leap.se/code/issues/8180>`_: Initialize OpenSSL context just once.
- Remove document content conversion to unicode. Users of API are responsible
  for only passing valid JSON to Soledad for storage.

Misc
~~~~
- Add ability to get information about sync phases for profiling purposes.
- Add script for setting up develop environment.
- Refactor bootstrap to remove shared db lock.
- Removed multiprocessing from encdecpool with some extra refactoring.
- Remove user_id argument from Soledad init.

Common
======

Features
~~~~~~~~
- Embed l2db, forking u1db.

Misc
~~~~
- Toxify tests.

0.8.0 - 18 Apr, 2016
++++++++++++++++++++

Client
======

Features
~~~~~~~~
- `#7656 <https://leap.se/code/issues/7656>`_: Emit multi-user aware events.
- Client will now send documents at a limited size batch due to changes on SyncTarget. The default limit is 500kB. Disabled by default.

Bugfixes
~~~~~~~~
- `#7503 <https://leap.se/code/issues/7503>`_: Do not signal sync completion if sync failed.
- Handle missing design doc at GET (get_sync_info). Soledad server can handle this during sync.

Misc
~~~~
- `#7195 <https://leap.se/code/issues/7195>`_: Use cryptography instead of pycryptopp.

Known Issues
~~~~~~~~~~~~
- Upload phase of client syncs is still quite slow. Enabling size limited batching
  can help, but you have to make sure that your server is compatible.

Server
======

Features
~~~~~~~~
- General performance improvements.
- `#7509 <https://leap.se/code/issues/7509>`_: Moves config directory from /etc/leap to /etc/soledad.
- Adds a new config parameter 'create_cmd', which allows sysadmin to specify
  which command will create a database. That command was added in
  pkg/create-user-db and debian package automates steps needed for sudo access.
- Read netrc path from configuration file for create-user-db command. 
- 'create-user-db' script now can be configured from soledad-server.conf when
  generating the user's security document.
- Migrating a user's database to newest design documents is now possible by
  using a parameter '--migrate-all' on 'create-user-db' script.
- Remove tsafe monkeypatch from SSL lib, as it was needed for Twisted <12
- Added two methods to start and finish a batch on backend. They can be used to
  change database behaviour, allowing batch operations to be optimized.

Common
======

Features
~~~~~~~~
- Add a sanitized command executor for database creation and re-enable user
  database creation on CouchServerState via command line.

Bugfixes
~~~~~~~~
- `#7626 <https://leap.se/code/issues/7626>`_: Subclass a leaky leap.common.couch exception to avoid depending on couch.
