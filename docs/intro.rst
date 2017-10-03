Introduction
============

Soledad consists of a client library and server daemon that allows applications
to securely share a common state among devices. The local application is
presented with a simple, document-centric searchable database API. Any data
saved to the database by the application is client-encrypted, backed up in the
cloud, and synchronized among a user’s devices. Soledad is cross-platform, open
source, scalable, and features a highly efficient synchronization algorithm.

Key aspects of Soledad include:

* **Client and server:** Soledad includes a :ref:`server daemon
  <soledad-server>` and a :ref:`client application library <soledad-client>`.

* **Client-side encrypted sync:** Soledad puts very little trust in the server
  by :ref:`encrypting all data <document-encryption>` before it is
  :ref:`synchronized <document-sync>` to the server and by limiting ways in
  which the server can modify the user’s data.

* **Encrypted local storage:** All data cached locally is :ref:`stored in an
  encrypted database <client-databases>`.

* **Document database:** An application using the Soledad client library is
  presented with a :ref:`document-centric database API <soledad-client-api>`
  for storage and sync. Documents may be indexed, searched, and versioned.

* **Encrypted attachments:** storage and synchronization of :ref:`blobs` is
  supported.

Soledad is an acronym of “Synchronization of Locally Encrypted Documents Among
Devices” and means “solitude” in Spanish.

See also:

.. toctree::
   :maxdepth: 1

   intro/data-availability
   intro/goals
   intro/related
