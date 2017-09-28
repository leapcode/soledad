.. Soledad documentation master file, created by
   sphinx-quickstart on Mon Feb 17 17:54:47 2014.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Soledad
================================================================

Synchronization of Locally Encrypted Data Among Devices.

What is Soledad?
----------------

Soledad is a client library and a server daemon that together allow
applications to securely share a common state among devices. It is `LEAP
<https://leap.se/>`_'s solution for mail delivery and for synchronizing
client-encrypted data among a user's devices that access an account in a LEAP
provider.

The local application is presented with a simple, document-centric searchable
database API. Any data saved to the database by the application is
client-encrypted, backed up in the cloud, and synchronized among a user's
devices. Soledad is cross-platform, open source, scalable, and features
a highly efficient synchronization algorithm.

Soledad Client and Server are written in Python using `Twisted
<https://twistedmatrix.com/>`_. Source code is available at `0xacab
<https://0xacab.org/leap/soledad>`_ and is licensed under the `GPLv3
<http://www.gnu.org/licenses/gpl.txt>`_. Client and server are packaged
together and distributed in `pypi
<https://pypi.python.org/pypi/leap.soledad>`_. `Debian packages
<https://deb.leap.se/>`_ are also provided for the server-side component.

Soledad documentation
---------------------

.. toctree::
   :maxdepth: 2

   server
   client
   reference
   development
   api

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

