Goals
=====

Security goals
--------------

* **Client-side encryption:** Before any data is synced to the cloud, it should
  be encrypted on the client device.

* **Encrypted local storage:** Any data cached in the client should be stored
  in an encrypted format.

* **Resistant to offline attacks:** Data stored on the server should be highly
  resistant to offline attacks (i.e. an attacker with a static copy of data
  stored on the server would have a very hard time discerning much from the
  data).

* **Resistant to online attacks:** Analysis of storing and retrieving data
  should not leak potentially sensitive information.

* **Resistance to data tampering:** The server should not be able to provide
  the client with old or bogus data for a document.

Synchronization goals
---------------------

* **Consistency:** multiple clients should all get sync'ed with the same data.

* **Selective sync:** the ability to partially sync data. For example, so
  a mobile device doesn’t need to sync all email attachments.

* **Multi-platform:** supports both desktop and mobile clients.

* **Quota:** the ability to identify how much storage space a user is taking up.

* **Scalable cloud:** distributed master-less storage on the cloud side, with
  no single point of failure.

* **Conflict resolution:** conflicts are flagged and handed off to the
  application logic to resolve.  Usability goals

* **Availability:** the user should always be able to access their data.

* **Recovery:** there should be a mechanism for a user to recover their data
  should they forget their password.

Known limitations
-----------------

These are currently known limitations:

* The server knows when the contents of a document have changed.

* There is no facility for sharing documents among multiple users.

* Soledad is not able to prevent server from withholding new documents or new
  revisions of a document.

* Deleted documents are never deleted, just emptied. Useful for security reasons, but could lead to DB bloat.

Non-goals
---------

* Soledad is not for filesystem synchronization, storage or backup. It provides
  an API for application code to synchronize and store arbitrary schema-less
  JSON documents in one big flat document database. One could model
  a filesystem on top of Soledad, but it would be a bad fit.

* Soledad is not intended for decentralized peer-to-peer synchronization,
  although the underlying synchronization protocol does not require a server.
  Soledad takes a cloud approach in order to ensure that a client has quick
  access to an available copy of the data.
