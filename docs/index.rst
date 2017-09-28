.. Soledad documentation master file, created by
   sphinx-quickstart on Mon Feb 17 17:54:47 2014.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Soledad: synchronization of locally encrypted data among devices
================================================================

Soledad consists of a client library and a server daemon that allow
applications to securely share a common state among devices. It is LEAP's
solution for synchronizing client-encrypted data among user's devices that
access a LEAP provider.


The local application is presented with a simple, document-centric searchable
database API. Any data saved to the database by the application is
client-encrypted, backed up in the cloud, and synchronized among a user's
devices. Soledad is cross-platform, open source, scalable, and features
a highly efficient synchronization algorithm.

The application is written in Python and the `source code
<https://0xacab.org/leap/soledad>`_ is available and licensed as free software.
Both client and server are `distributed through pypi
<https://pypi.python.org/pypi/leap.soledad>`_, and `Debian packages
<https://deb.leap.se/>`_ are also provided for the server-side component.

.. toctree::
   :maxdepth: 2

   server
   client
   reference
   development
   migrations

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

