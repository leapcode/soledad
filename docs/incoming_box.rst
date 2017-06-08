Soledad "Incoming Box" Functional Specification
===============================================

*A mechanism for writing encrypted data into a user database, to be processed and synced afterwards.*

* **Version**: 0.1.0
* **Date**: 8 jun 2017
* **Authors**: kali, vshyba

.. contents::
   :local:

Overview
--------
The ``Incoming Box`` (or, in some contexts, ``incoming pools``) are a new feature of Soledad, beginning with release 0.9.7, that aim at improving the mechanism by which external trusted applications can write encrypted data into a specific user database, from where it will be further processed by the soledad client.

Design Goal
-----------
Use the particular story about MX delivery to guide the design of a general mechanism that makes sense in the context of Soledad as a generic Encrypted Database Solution.
The final solution should still be able to be the backend for different types of applications, without introducing abstractions that are too tied to the encrypted email use case.

Features
--------
1. Deliver data (encrypted with a public-key mechanism) into a particular user's database in the server.
2. Provide a mechanism by which Soledad Client, acting on behalf of an user, can download the encrypted data, decrypt it, process it in any needed way, and eventually store it again in the conventional main storage that Soledad provides.
3. Allow to purge a document that has been correctly processed
4. Allow to mark a document that has failed to be decrypted, to avoid trying to decrypt it in every processing loop

Conventions
-----------

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL
NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED",  "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
`RFC 2119`_.

.. _`RFC 2119`: https://www.ietf.org/rfc/rfc2119.txt

Terminology
-----------
- ``Blob`` refers to an encrypted payload that is stored by soledad server as-is. It is assumed that the blob was end-to-end encrypted by an external component before being reaching the server. [link to Soledad BLOBS SPEC]
- A ``BlobBackend`` implementation is a particular backend setup by the Soledad Server that stores all the blobs that a given user owns. For now, only Filesystem Backend is provided.
- ``Incoming Box`` is a subset of the Blob storage space that provides semantics to store and process incoming message data chronologically. 
- An ``Incoming Message`` makes reference to an abstract entity that matches exactly one message item, no matter how it is stored (ie, docs vs. blobs, single blob vs chunked, etc). It can represent one Email Message, one URL, an uploaded File, etc.
- By ``Message Processing`` we understand the sequence of downloading an incoming message, decrypting it, transform it in any needed way, and deleting the original incoming message.

Components
----------
* Soledad Server is the particular implementation that runs in the server (the
  twisted implementation is the only one to the moment). This exposes several
  endpoints (document store, blob storage, incoming message box) that, for
  simplicity, will be assumed to run under the same process space.
* The BlobsBackend is the particular implementation of the BlobsBackend
  interface that the server has configured
* Soledad Client is the particular client that runs in different desktop
  replicas (the twisted implementation is the only one to the moment). It
  executes a sync periodically, that syncs all metadata docs, and then downloads
  the linked blobs on demand.
* BlobsManager is the component that orchestrates the uploads/downloads and
  storage in the client side. The client storage backend currently is SQLCipher,
  using the BLOB type.
* A Trusted Application is any application that is authorized to write data into
  the user incoming box. Initially, LEAP's Encrypting Remailer Proxy (MX, for
  short) is going to be the main trusted application that will drive the
  development of the Incoming Box.
* On the client side, there's the client counterpart of the trusted application,
  that consumes the incoming messages. In the encrypted email case, this
  component is the incoming service in Bitmask Mail. It is assumed, for
  simplicity, that the consuming app shares the process memory space with the
  soledad client, but this doesn't have to hold true in the future.

The User Experience
-------------------
* For the end user, the behaviour of the Incoming Box in Soledad is completely
  transparent. Periodically, new "messages" of any particular type will appear
  on the Local Storage, without any other intervention that introducing the
  master passphrase.
* From the application developer perspective, the "Incoming Box" will appear as
  an iterable set that, in a given moment, will return all the messages that are
  yet pending to be processed. The request can be qualified by some modifiers
  (sorting, skipping, pagination).

Writing Data Into The Incoming Box
----------------------------------
* Any payload MUST arrive already encrypted to the endpoint of the Incoming
  Box. Soledad, at v1, will not add any encryption to the payloads.
* The knowledge to decrypt a given payload, at v1, is shared by both the Trusted
  App that delivered the payload into the user Incoming Box (MX in this case),
  and the domain-specific application that processes the incoming message on the
  client side (incoming service in bitmask mail, in this case).
* Incoming Boxes MUST NOT be writeable by any other user or any external applications.

Writing Data When User Quota is Exceeeded
-----------------------------------------
* The server SHOULD copy the payload to the permanent storage in the user database only after checking that the user current storage plus the payload size does not exceed the allowed quota, if any, plus a given tolerance limit.
* The Trusted Application SHOULD receive an error message as a response to its storage request, so that it can register the failure to store the date, or inform the sender in the case in which the trusted app is acting as a delegate to deliver a message.

Authentication
--------------
* The Trusted Application (MX) and the incoming box MUST share a secret, that is written into the configuration files of both services.
* The Incoming Box MUST NOT be accessible as a public service from the outside.

Listing All Incoming Messages
-----------------------------
* Soledad server will list all the messages in the Incoming Box every time that a client request it.
* The server MUST return the number of pending messages.
* The server SHOULD skip messages from the returned set beyond a given size limit, if the client requests it so.
* The server MAY allow pagination.

Processing Incoming Messages
-----------------------------
* The default state for a message in the Incoming Box is PENDING
* Before processing any message, a client MUST mark its blob as "PROCESSING",
  reserving the message for itself so other replicas don't try to repeat
  processing.
* Any replica MAY expire the PROCESSING flag if the defined
  PROCESSING_THRESHOLD is passed, to avoid data left unusable by stalled clients.
* A message marked as PROCESSING MUST only be marked as PROCESSED by the replica
  that marked it, which signals that is ready to be deleted.
* A Client MUST mark an incoming message as PROCESSED only when there are
  guarantees that the incoming message has been processed without errors, and the
  parts resulting of its processing are acknowleged to have been uploaded
  successfully to the central replica.

Marking a Message as Failed
---------------------------

* A client SHOULD be able to mark a given message as temporarily failed. This
  covers the case in which a given message failed to be decrypted by a
  implementation-related reason (for instance: uncatched exceptions related to
  encoding, wrong format in serialization). The rationale is that we don't want
  to increase overhead by retrying decryption on every syncing loop, but we
  don't want to discard a particular payload. Future versions of the client
  might implement bugfixes or workarounds to try succesful 
* Therefore, a client SHOULD be able to add its own version when it marks a
  message as temporarily failed. 
* After some versions, a message should be able to be marked as permanently
  failed

Deleting Incoming Messagges
---------------------------
* Any message in the ``Incoming Box`` marked as PROCESSED MAY be deleted by ANY client replica.
* Any message in the ``Incoming Box`` marked as PERMANENTLY FAILED MAY be deleted by ANY client replica.

Implementation: Server Blob Backend
-----------------------------------
In the Server Side, the implementation of the ``Incoming Box`` MUST be done
exclusively at the level of the BlobStorage.  The Blobs implementation in both
Soledad Server and Client have enough knowledge of the incoming box semantics to
allow its processing to be done without resorting to writing documents in the
main soledad json storage.

Preffix Namespaces
~~~~~~~~~~~~~~~~~~

The ``Incoming Box`` endpoint should reserve a uuid for any incoming blob, qualified
by a reserved preffix per each Trusted App ('incoming-mx'). This is the main
mechanism to store the pool of "Incoming Messages" inside the bigger namespace
of Blobs.

This means that the general Blob spec MAY contemplate a mechanism to limiting
the listing of Blobs to a particular incremental preffix.

LIST commands
~~~~~~~~~~~~~

The server MUST reply to several LIST commands, qualified by namespace and by
other query parameters. Some of these commands are optional, but the server
SHOULD reply to them signaling that they are not supported by the
implementation.

LIST COUNT
++++++++++
Returns the number of messages in the incoming box. If pending is True, only the subset marked as pending.

Example::

  list_count('incoming/mx', pending=True)

LIST GET ALL
++++++++++++
The response to a "get all" request by a client should return all the blobs under a given namespace.
It returns a list of uuids.

Example::

  list_get_all('incoming/mx')


LIST QUALIFIERS
+++++++++++++++

In order to improve performance and responsiveness, a list request MAY be
qualified by the following parameters that the server SHOULD satisfy.
The responses are, in any case, a list of the ``uuids`` of the Blobs.

.. note: Should we extend this to other structure? Like a dict, containing
         timestamps and sizes.

- Pagination
- Skip by SIZE THRESHOLD
- Include messages with PROCESSING flag (replica uuid)


LIST PAGINATION
+++++++++++++++

* ``LIMIT``: number of messages to receive in a single response
* ``PAGE``: when used with limit, which page to return (limited by the number in LIMIT). (Note that, in reality, any client will just process the first page under a normal functioning mode).

Example::

  list_get_all('incoming/mx', limit=20, page=1)

LIST SKIP-BY-SIZE
+++++++++++++++++

* SIZE_LIMIT: skips messages bigger than a given size limit, to avoid downloading payloads too big when client is interested in a quick list of incoming messages.

Example::

  list_get_all('incoming/mx', size_limit=10MB)

LIST ORDER_BY
+++++++++++++

Server CAN allow an order_by parameter in LIST commands.

* Chronological order (by default, implicit, older first)
* Reverse Chronological order (newest first)

Example::

  list_get_all('incoming/mx', order_by='date')

Example::

  list_get_all('incoming/mx', order_by='date_reverse')

Implementation: Client side processing
--------------------------------------

* To begin a processing round, the client starts by asking a list of the pending messages.
* To avoid potentially costly traversals, the client limits the query to the most recent N blobs flagged as PENDING.
* To avoid downloading very big attachments, client can limit the query on a first pass to all pending blobs  smaller than X Kb.

Example::

  incoming_box('mx').get_all(limit=100, size_limit=100)

* After getting the PENDING list, the client MUST start downloading the blobs according to the uuids returned. 
* Download happens as chronological order, from the list. It can also happen concurrently or one by one, as configured.
* The client MUST provide a mechanism so that any trusted application (bitmask mail) can execute a callback for each downloaded message to be processed.
* Attention SHOULD be payed to the callbacks not blocking the main event loop of the client.


Example 1, serial::

  for blob_id in pending_list:
    blob = yield blob_manager.get(blob_id, incoming=True) # this will trigger a local save as well
    yield blob_manager.remote_set_flags(blob_id, ['PENDING'])
    success = yield process(blob)
    if success:
      yield blob_manager.delete(blob_id)
    else:
      yield blob_manager.set_flags(blob_id, ['FAILED'])


Example 2, concurrent::

  def callback(blob_id, blob):
    yield blob_manager.remote_set_flags(blob_id, ['PENDING', self.replica_uuid])
    success = yield process(blob)
    if success:
      yield blob_manager.delete(blob_id)
    else:
      yield blob_manager.set_flags(blob_id, ['FAILED'])
  for blob_id in pending_list:
    blob_manager.get(blob_id, incoming=True)
    d.addCallback(callback)
    deferreds.append(d)
  yield gatherResults(deferreds)


Future Features
---------------

Still subject to discussion, but some features that are desired for future iterations are:

* Provide a mechanism to retry documents marked as failed by previous revisions.
* Internalizing public key infrastructure (using ECC).
* ACLs to allow other users to push documents to an user Incoming Box.
* Provide alternative implementations of the Incoming Box endopoint (for example, in Rust)
