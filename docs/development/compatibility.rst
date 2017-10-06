Compatibility
=============

This page keeps notes about compatibility between different versions of Soledad
and between Soledad and other components of the `LEAP Platform
<https://leap.se/docs/platform>`_.

* Upgrades of Soledad Server < 0.9.0 to >= 0.9.0 need database migration
  because older code used to use CouchDB's design documents, while newer code
  got rid of that because it made everything cpu and memory hungry. See `the
  documentation
  <http://soledad.readthedocs.io/en/latest/migrations.html#soledad-server-0-8-to-0-9-couch-database-schema-migration-needed>`_
  for more information.

* Soledad Server >= 0.7.0 is incompatible with client < 0.7.0 because of
  modifications on encrypted document MAC calculation.

* Soledad Server >= 0.7.0 is incompatible with LEAP Platform < 0.6.1 because
  that platform version implements ephemeral tokens databases and Soledad
  Server needs to act accordingly.
