.. _document-sync:

Document synchronization
========================

Soledad follows `the U1DB synchronization protocol
<https://pythonhosted.org/u1db/conflicts.html>`_ with some modifications:

* A synchronization always happens between the Soledad Server and one Soledad
  Client. Many clients can synchronize with the same server.

* Soledad Client :ref:`always encrypts <document-encryption>` before sending
  data to the server.

* Soledad Client refuses to receive a document if it is encrypted and the MAC
  is incorrect.

* Soledad Server doesn't try to decide about document convergence based on the
  document's content, because the content is client-encrypted.

Synchronization protocol
------------------------

Synchronization between the Soledad Server and one Soledad Client consists of
the following steps:

1. The client asks the server for the information it has stored about the last
   time they have synchronized (if ever).

2. The client validates that its information regarding the last synchronization
   is consistent with the server's information, and raises an error if not.
   (This could happen for instance if one of the replicas was lost and restored
   from backup, or if a user inadvertently tries to synchronize a copied
   database.)

3. The client generates a list of changes since the last change the server
   knows of.

4. The client checks what the last change is it knows about on the server.

5. If there have been no changes on either side that the other side has not
   seen, the synchronization stops here.

6. The client encrypts and sends the changed documents to the server, along
   with what the latest change is that it knows about on the server.

7. The server processes the changed documents, and records the client's latest
   change.

8. The server responds with the documents that have changes that the client
   does not yet know about.

9. The client decrypts and processes the changed documents, and records the
   server's latest change.

10. If the client has seen no changes unrelated to the synchronization during
    this whole process, it now sends the server what its latest change is, so
    that the next synchronization does not have to consider changes that were
    the result of this one.

Synchronization metadata
------------------------

The synchronization information stored on each database replica consists of:

* The replica id of the other replica. (Which should be globally unique
  identifier to distinguish database replicas from one another.)

* The last known generation and transaction id of the other replica.

* The generation and transaction id of this replica at the time of the most
  recent succesfully completed synchronization with the other replica.

Transactions
------------

Any change to any document in a database constitutes a transaction. Each
transaction increases the database generation by 1, and is assigned
a transaction id, which is meant to be a unique random string paired with each
generation.

The transaction id can be used to detect the case where replica A and replica
B have previously synchronized at generation N, and subsequently replica B is
somehow reverted to an earlier generation (say, a restore from backup, or
somebody made a copy of the database file of replica B at generation < N, and
tries to synchronize that), and then new changes are made to it. It could end
up at generation N again, but with completely different data.

Having random unique transaction ids will allow replica A to detect this
situation, and refuse to synchronize to prevent data loss. (Lesson to be
learned from this: do not copy databases around, that is what synchronization
is for.)
