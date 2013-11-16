repackaging howto
=================

How to repackage latest code
----------------------------

Enter debian branch::

 git checkout debian

Merge your latest and greatest::

 git merge develop

Bump the changelog::

 vim debian/changelog

dch should also get you there, adding a new entry.

Edit the changelog so you get a new version (this is the version
that apt will report). For example, change::

  soledad-common (0.3.4) unstable; urgency=low

to::

  soledad-common (0.3.4-1~testing_frobnication) unstable; urgency=low


Last, but not least, freeze the debian version::

 python setup.py freeze_debianver

It might be a good idea to edit by hand the version string
under _version too, so it's clear that you're packaging some bleeding
edge not to be confused with latest stable packages.

And now you can happily repackage for your own deploys::

  debuild -us -uc
