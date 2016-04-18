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
