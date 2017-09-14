Soledad Server
==============

A U1DB server that stores data using CouchDB as its persistence layer.

.. contents::
   :local:

General information
-------------------

This is written as a Twisted application and intended to be run using the
twistd command. To start the soledad server, run:

.. code-block:: bash

    twistd -n --python /path/to/leap/soledad/server/server.tac

An systemd script is included and will be installed system wide to make it
feasible to start and stop the Soledad server service using a standard
interface.

Server database organization
----------------------------

Soledad Server works with one database per user and one shared database in
which user's encrypted secrets might be stored.

User database
~~~~~~~~~~~~~

Users' databases in the server are named 'user-<uuid>' and Soledad Client
may perform synchronization between its local replicas and the user's
database in the server. Authorization for creating, updating, deleting and
retrieving information about the user database as well as performing
synchronization is handled by the `leap.soledad.server.auth` module.

Shared database
~~~~~~~~~~~~~~~

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

.. _server-config-file:

Server Configuration File
-------------------------

Soledad Server looks for a configuration file in
``/etc/soledad/soledad-server.conf`` and will read the following configuration
options from the ``[soledad-server]`` section:

==================== =============================================== ================================
Option               Description                                     Default value
==================== =============================================== ================================
couch_url            The URL of the CouchDB backend storage.         ``http://localhost:5984``
create_cmd           The shell command to create user databases.     None
admin_netrc          The netrc file to be used for authenticating    ``/etc/couchdb/couchdb.netrc``
                     with the CouchDB backend storage.
batching             Whether to use batching capabilities for        ``true``
                     synchronization.
blobs                Whether to provide the Blobs functionality or   ``false``
                     not.
blobs_path           The path for blobs storage in the server's file ``/var/lib/soledad/blobs``
                     system.
services_tokens_file The file containing authentication tokens for   ``/etc/soledad/services.tokens``
                     services provided through the Services API.
==================== =============================================== ================================
