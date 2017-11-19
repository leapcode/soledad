==============
soledad-server
==============

-----------------------
Run the Soledad Server.
-----------------------

:Author: The LEAP Encryption Access Project https://leap.se
:Copyright: GPLv3+
:Manual section: 1
:Manual group: General Commands Manual

SYNOPSIS
========

``soledad-server`` [-v|--version] [-h|--help]

DESCRIPTION
===========

``soledad-server`` runs the Soledad Server, which consists of two HTTP APIs
listening on different ports. By default, the ``Users HTTP API`` is provided
publicly in port 2323 through TLS-encrypted connections, and the ``Services
HTTP API`` is provided locally in port 2525 through plaintext connections.

For more information and the complete documentation, see
`https://soledad.readthedocs.io/` and `https://leap.se/en/docs/design/soledad`.

OPTIONS
=======

--version
  Print the version of the server and exit.

-h, --help
  Print a help message and exit.

FILES
=====

/etc/soledad/soledad-server.conf
  The Soledad Server configuration file. See the possible options and their
  default values in
  `/usr/share/doc/soledad-server/soledad-server.conf.default`.

/etc/soledad/services.tokens
  File containing authentication information for local services. Each line
  should be a `username`:`token` pair.

ENVIRONMENT
===========

HTTPS_PORT
  Public HTTPS Users API (2323 by default).

LOCAL_SERVICES_PORT
  Local HTTP Services API port (2525 by default).

SOLEDAD_SERVER_CONFIG_FILE
  Load configuration from this file instead of using the default one
  (*/etc/soledad/soledad-server.conf*).

SOLEDAD_COUCH_URL
  If set, use this URL for accessing couchdb (overrides the configuration file).

SOLEDAD_HTTP_PERSIST
  If set, persist HTTP connections.

SOLEDAD_USE_PYTHON_LOGGING
  If set, use python logging instead of twisted's logger.

SOLEDAD_LOG_TO_STDOUT
  If set, log to standard output.

BUGS
====

Please report any bugs to https://leap.se/code/projects/report-issues
