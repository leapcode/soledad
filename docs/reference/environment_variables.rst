Environment Variables
=====================

Some environment variables affect the behaviour of Soledad:

============================== =============== =================================
variable                       affects         description
============================== =============== =================================
``SOLEDAD_HTTP_PERSIST``       client          persist HTTP connections.
``SOLEDAD_THROTTLING``         client          enable bandwidth throttling.
``SOLEDAD_USE_PYTHON_LOGGING`` client / server use python logging instead of
                                               twisted's logger.
``SOLEDAD_LOG_TO_STDOUT``      client / server log to standard output.
``SOLEDAD_COUCH_URL``          server          override the CouchDB url.
``SOLEDAD_SERVER_CONFIG_FILE`` server          use this configuration file
                                               instead of the default one.
``LOCAL_SERVICES_PORT``        server          which port to use for local
                                               TCP services.
``HTTPS_PORT``                 server          which port to use for public
                                               HTTPS services.
============================== =============== =================================
