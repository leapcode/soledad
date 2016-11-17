Couchdb Docker image
====================

This directory contains rules to build a custom couchdb docker image to be
provided as backend to soledad server.

Type `make` to build the image.

Differences between this image and the official one:

  - add the "nodelay" socket option on the httpd section of the config file
    (see: https://leap.se/code/issues/8264).
