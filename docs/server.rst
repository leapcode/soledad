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

Running
-------

This is written as a Twisted application and intended to be run using the
twistd command. To start the soledad server, run:

.. code-block:: bash

    twistd -n --python /path/to/leap/soledad/server/server.tac

An systemd script is included in the `Debian packages
<http://deb.leap.se/repository/>`_ to make it feasible to start and stop the
Soledad server service using a standard interface.
