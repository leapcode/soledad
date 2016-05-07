0.8.1 - ...
++++++++++++++++++++

Please add lines to this file, they will be moved to the CHANGELOG.rst during
the next release.

There are two template lines for each category, use them as reference.

I've added a new category `Misc` so we can track doc/style/packaging stuff.

Features
~~~~~~~~
- Add recovery document format version for future migrations.
- Use DeferredLock instead of its locking cousin.
- `#1234 <https://leap.se/code/issues/1234>`_: Description of the new feature corresponding with issue #1234.
- New feature without related issue number.

Bugfixes
~~~~~~~~
- `#1235 <https://leap.se/code/issues/1235>`_: Description for the fixed stuff corresponding with issue #1235.
- Remove document content conversion to unicode. Users of API are responsible
  for only passing valid JSON to Soledad for storage.
- Bugfix without related issue number.

Misc
~~~~
- Add ability to get information about sync phases for profiling purposes.
- Add script for setting up develop environment.
- Refactor bootstrap to remove shared db lock.
- `#1236 <https://leap.se/code/issues/1236>`_: Description of the new feature corresponding with issue #1236.
- Some change without issue number.

Known Issues
~~~~~~~~~~~~
- `#1236 <https://leap.se/code/issues/1236>`_: Description of the known issue corresponding with issue #1236.
