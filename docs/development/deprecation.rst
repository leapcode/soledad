Backwards-compatibility and deprecation policy
==============================================

Since Soledad has not reached a stable `1.0` release yet, no guarantees are made
about the stability of its API or the backwards-compatibility of any given
version.

Currently, the internal storage representation is experimenting changes that
will take some time to mature and settle up. For the moment, no given SOLEDAD
release is offering any backwards-compatibility guarantees.

Although serious efforts are being made to ensure no data is corrupted or lost
while upgrading soledad versions, it's not advised to use SOLEDAD for any
critical storage at the moment, or to upgrade versions without any external data
backup (for instance, an email application that uses SOLEDAD should allow to
export mail data or PGP keys in a convertible format before upgrading).

Deprecation Policy
------------------

The points above standing, the development team behind SOLEDAD will strive to
provide clear migration paths between any two given, consecutive **minor
releases**, in an automated form wherever possible.

This means, for example, that a migration script will be provided with the
``0.10`` release, to migrate data stored by any of the ``0.9.x`` soledad
versions. Another script will be provided to migrate from  ``0.10`` to ``0.11``,
etc (but not, for instance, from ``0.8`` to ``0.10``).

At the same time, there's a backwards-compatibility policy of **deprecating APIs
after 2 minor releases**. This means that a feature will start to be marked as
deprecated in ``0.10``, with a warning being raised for 2 minor releases, and
the API will disappear completely no sooner than in ``0.12``.

