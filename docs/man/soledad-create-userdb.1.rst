=====================
soledad-create-userdb
=====================

------------------------------------------------------------------------
Create a user database for use with Soledad Server in the LEAP Platform.
------------------------------------------------------------------------

:Author: The LEAP Encryption Access Project https://leap.se
:Copyright: GPLv3+
:Manual section: 1
:Manual group: General Commands Manual

SYNOPSIS
========

``soledad-create-userdb`` [-h] `dbname`

DESCRIPTION
===========

``soledad-create-userdb`` is a command used by Soledad Server to create user
databases for use with the LEAP Platform.

The current database backend used by the LEAP Platform is CouchDB. This command
will parse the Soledad Server configuration file to find the path for a netrc
file with the administrative CouchDB credentials. See the **FILES** section
below for more information on this. 

This command is meant to be run by the `soledad` user in the system, which
should have special privileges so it can read the CouchDB administrative
credentials from the netrc file pointed by the Soledad Server configuration
file.

OPTIONS
=======

`dbname`
  The name of the database to be created.

-h, --help
  Print a help message and exit.

FILES
=====

/etc/soledad/soledad-server.conf
  The Soledad Server configuration file. The path to a netrc file with CouchDB
  administrative credentials should be set in this file with the option
  ``admin_netrc`` under the section ``[soledad-server]``.

ENVIRONMENT
===========

SOLEDAD_SERVER_CONFIG_FILE
  If set, the command will parse the configuration file pointed by this variable
  instead of the default one in */etc/soledad/soledad-server.conf*.

SOLEDAD_BYPASS_AUTH
  If set, the command will not try to load the CouchDB administrative
  credentials and URI from a configuration file. Instead, it will use
  ``http://127.0.0.1:5984/`` as URI (without username and password).

BUGS
====

Please report any bugs to https://leap.se/code/projects/report-issues
