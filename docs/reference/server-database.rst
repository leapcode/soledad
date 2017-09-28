Server-side databases
=====================

Soledad Server works with one database per user and one shared database in
which user's encrypted secrets might be stored.

User databases
--------------

User databases in the server are named 'user-<uuid>' and Soledad Client may
perform synchronization between its local replicas and the user's database in
the server. Authorization for creating, updating, deleting and retrieving
information about the user database as well as performing synchronization is
handled by the `leap.soledad.server.auth` module.

Shared database
---------------

Each user may store password-encrypted recovery data in the shared database.

Recovery documents are stored in the database without any information that
may identify the user. In order to achieve this, the doc_id of recovery
documents are obtained as a hash of the user's uid and the user's password.
User's must have a valid token to interact with recovery documents, but the
server does not perform further authentication because it has no way to know
which recovery document belongs to each user.

This has some implications:

  * The security of the recovery document doc_id, and thus of access to the
    recovery document (encrypted) content, as well as tampering with the
    stored data, all rely on the difficulty of obtaining the user's password
    (supposing the user's uid is somewhat public) and the security of the hash
    function used to calculate the doc_id.

  * The security of the content of a recovery document relies on the
    difficulty of obtaining the user's password.

  * If the user looses his/her password, he/she will not be able to obtain the
    recovery document.

  * Because of the above, it is recommended that recovery documents expire
    (not implemented yet) to prevent excess storage.

The authorization for creating, updating, deleting and retrieving recovery
documents on the shared database is handled by `leap.soledad.server.auth`
module.

