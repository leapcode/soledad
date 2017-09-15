Soledad "Incoming Box" Specification
====================================

*A mechanism for Trusted Applications to write encrypted data for a given user into the Soledad Server, which will sync it to the client to be processed afterwards.*

* **Version**: 0.2.0
* **Date**: 27 jun 2017
* **Authors**: kali, drebs, vshyba

.. contents::
   :local:

Overview
--------
The ``Incoming Box`` is a new feature of Soledad, (from 0.10 forward), that aim at improving the mechanism by which external Trusted Applications can write data that will be delievered to a user's database in the server side, from where it will be further processed by the Soledad Client. This processing includes decrypting the payload, since the incoming data is expected to be encrypted by the Trusted Application.

Design Goal
-----------
Use the particular story about MX delivery to guide the design of a general mechanism that makes sense in the context of Soledad as a generic Encrypted Database Solution.
The final solution should still be able to be the backend for different types of applications, without introducing abstractions that are too tied to the encrypted email use case.

Features
--------
1. Deliver data (expected to be encrypted with a public-key mechanism) to the Soledad Server, so that it is written into the data space for a particular user.
2. Provide a mechanism by which Soledad Client, acting on behalf of an user, can download the data, process it in any needed way, and eventually store it again in the conventional main storage that Soledad provides. Since the data is expected to be encrypted by the delivery party, the client-side processing includes any decryption step if needed.
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
- ``Blob`` refers to an encrypted payload that is stored by soledad server as-is. It is assumed that the blob was end-to-end encrypted by an external component before reaching the server. (See the :ref:`Blobs Spec <blobs-spec>` for more detail)
- A ``BlobsBackend`` implementation is a particular backend setup by the Soledad Server that stores all the blobs that a given user owns. For now, only a filesystem backend is provided.
- An ``Incoming Message`` makes reference to the representation of an abstract entity that matches exactly one message item, no matter how it is stored (ie, docs vs. blobs, single blob vs chunked, etc). It can represent one Email Message, one URL, an uploaded File, etc. For the purpose of the email use case, an Incoming Message refers to the encrypted message that MX has delivered to the incoming endpoint, which is pgp-encrypted, and can have been further obfuscated.
- By ``Message Processing`` we understand the sequence of downloading an incoming message, decrypting it, transform it in any needed way, and deleting the original incoming message.
- An ``Incoming Box`` is a subset of the Blobs stored for an user, together with the mechanisms that provide semantics to store, list, fetch and process incoming message data chronologically. 

Components
----------
* Soledad Server is the particular implementation that runs in the server (the
  twisted implementation is the only one to the moment). This exposes several
  endpoints (documents synchronization, blob storage, incoming message box).
* BlobsBackend is a particular implementation of the IBlobsBackend interface,
  such as FilesystemBlobsBackend, that the server has been configured to use.
* Soledad Client is the particular client that runs in different desktop
  replicas in the u1db sense (the twisted implementation is the only one to the
  moment). It executes a sync periodically, that syncs all metadata docs
  (soledad l2db json documents), and then downloads the blobs on demand. The
  blobs that need to be synced are both the encrypted blobs that are linked from
  metadata docs, and in this case the blobs stored in the space for a given
  Incoming Box.
* BlobsManager is the component that orchestrates the uploads/downloads and
  storage in the client side. The client storage backend currently is SQLCipher,
  using the BLOB type.
* A Trusted Application is any application that is authorized to write data into
  the user incoming box. Initially, LEAP's Encrypting Remailer Proxy (MX, for
  short) is going to be the main trusted application that will drive the
  development of the Incoming Box.
* Client Trusted Application Consumer is any implementation of Soledad's client
  IIncomingBoxConsumer, which is the interface that the client counterpart of
  the Trusted Application needs to implement in order to receive messages. It
  provides implementation for processing and saving Incoming Messages. In the
  encrypted email case, this component is the Incoming Mail Service in Bitmask
  Mail.

The User Experience
-------------------
* From the end user perspective (ie, the user of Bitmask Mail in this case),
  the behaviour of the Incoming Box client in Soledad is completely
  transparent.  Periodically, Soledad will call the Client Trusted Application
  Consumer with new "messages" of any particular type backed by the Soledad
  Client Storage, without any other intervention that introducing the master
  passphrase.
  
* From the client API perspective (considering the user is a Client Trusted
  Application developer), all it needs to do is to implement
  ``IIncomingBoxConsumer`` interface and register this new consumer on Soledad
  API, telling the desired namespace it wants to consume messages from.
  Soledad will then take care of calling the consumer back for processing and
  saving of Incoming Messages.

Writing Data Into The Incoming Box
----------------------------------
* Any payload MUST arrive already encrypted to the endpoint of the Incoming Box.
  Soledad Server, at version 1 of this spec, will not add any encryption to the
  payloads.
* The details of the encryption scheme used by the Trusted Application to
  encrypt the delivered payload (MX in this case) MUST be shared with the
  domain-specific application that processes the incoming message on the client
  side (Incoming Mail Service in Bitmask Mail, in this case). This means that
  the encryption schema MUST be communicated to the Incoming Box API in the
  moment of the delivery.
* Incoming Boxes MUST NOT be writeable by any other user or any external
  applications.

Authentication
--------------
* The Trusted Application and the Soledad Server exposing the Incoming Box
  endpoint MUST share a secret, that is written into the configuration files of
  both services.
* The Incoming Box MUST NOT be accessible as a public service from the outside.

Listing All Incoming Messages
-----------------------------
* Soledad server will list all the messages in the Incoming Box every time that a client requests it.
* The server MUST return the number of pending messages.
* The server SHOULD skip messages from the returned set beyond a given size limit, if the client requests it so.
* The server MAY allow pagination.

Processing Incoming Messages
-----------------------------
* The Blobs containing the Incoming Messages need the capability to be marked
  as in one of the following states: PENDING, PROCESSING, PROCESSED, FAILED.
* The default state for a new message in the Incoming Box is PENDING.
* Before delivering a Message to a client for processing, the server MUST mark
  the blob that contains it as PROCESSING, reserving the message for this
  client so other replicas don't try to repeat the processing.
* The server MAY expire the PROCESSING flag if the defined PROCESSING_THRESHOLD
  is passed, to avoid data left unusable by stalled clients.
* A message marked as PROCESSING MUST only be marked as PROCESSED by the server
  when it receives a confirmation by the replica that initiated the download
  request. This confirmation signals that the message is ready to be deleted.
* A Client MUST request to the server to mark an incoming message as PROCESSED
  only when there are guarantees that the incoming message has been processed
  without errors, and the parts resulting of its processing are acknowleged to
  have been uploaded successfully to the central replica in the server.

Marking a Message as Failed
---------------------------

* A Soledad Client MUST be able to mark a given message as FAILED. This covers
  the case in which a given message failed to be decrypted by a
  implementation-related reason (for instance: uncatched exceptions related to
  encoding, wrong format in serialization). The rationale is that we don't want
  to increase overhead by retrying decryption on every syncing loop, but we
  don't want to discard a particular payload. Future versions of the client
  might implement bugfixes or workarounds to try succeed in the processing.
* Therefore, a Soledad Client SHOULD be able to add its own version when it
  marks a message as temporarily failed.
* After some versions, a message SHOULD be able to be marked as permanently
  failed.
* Reservation MUST be released, as any other replica MUST be able to pick the
  message to retry. This covers the case of a new replica being added with an
  updated version, which can be able to handle the failure.

Deleting Incoming Messagges
---------------------------
* Any message in the ``Incoming Box`` marked as PROCESSED MAY be deleted by
  the server.
* Any message in the ``Incoming Box`` marked as PERMANENTLY FAILED MAY be deleted by the server.

Implementation Details
----------------------

Server Blob Backend
+++++++++++++++++++
In the Server Side, the implementation of the ``Incoming Box`` MUST be done
exclusively at the level of the BlobStorage.  The Blobs implementation in both
Soledad Server and Client have enough knowledge of the incoming box semantics
to allow its processing to be done without resorting to writing documents in
the main soledad json storage.
 
For simplicity, the ``IncomingBox`` endpoint is assumed to be running under the
same process space than the rest of the Soledad Server.

Preffix Namespaces
~~~~~~~~~~~~~~~~~~

The Trusted Application code responsible for delivering messages into Soledad
Server ``Incoming Box`` endpoint MUST specify as a request parameter the
dedicated namespace that it desires to use and be authorized to write into it.
This is done so Soledad can list, filter, flag, fetch and reserve only messages
known to the Trusted Application, avoiding to mix operations with blobs from
the global namespace or messages from another Trusted Application.

LIST commands
~~~~~~~~~~~~~

The server MUST reply to several LIST commands, qualified by namespace and by
other query parameters. Some of these commands are optional, but the server
SHOULD reply to them signaling that they are not supported by the implementation.

The Server MUST return a list with the UIDs of the messages.

Supported listing features are:
* Filter by namespace, which selects the namespace to do the list operation.
* Filter by flag, which lists only messages/blobs marked with the provided flag.
* Ordering, which changes the order of listing, such as older or newer first.
* Count, which returns the total list size after filtering, instead of the list itself.

Client side Processing
++++++++++++++++++++++

It is assumed, for simplicity, that the Trusted Application consumer
implementation shares the process memory space with the soledad client, but
this doesn't have to hold true in the future.

The class responsible for client side processing on Soledad Client is named
``IncomingBoxProcessingLoop``. Its role is to orchestrate processing with the
Incoming Box features on server side, so it can deliver messages to it's
registered Trusted Application Consumers.

* To begin a processing round, the client starts by asking a list of the
  pending messages.
* To avoid potentially costly traversals, the client limits the query to the
  most recent N blobs flagged as PENDING.
* To avoid downloading bulky messages in the incoming queue (for example,
  messages with very big attachments), the client MAY limit the query on a
  first pass to all pending blobs  smaller than X Kb.
* After getting the list of Incoming Messages in the PENDING set, the client
  MUST start downloading the blobs according to the uuids returned.
* Download SHOULD happen in chronological order, from the list. Download may
  happen in several modalities: concurrently, or sequentially.
* The Soledad Client MUST provide a mechanism so that any clientside
  counterpart of the Trusted Application (ie: Bitmask Mail) can register a
  consumer for processing and saving each downloaded message.
* In the reference implementation, since the consumers that the client
  registers are executed in the common event loop of the Soledad Client
  process, attention SHOULD be payed to the callbacks not blocking the main
  event loop.

Example of a Trusted Application Client Consumer:

```python
@implementer(interfaces.IIncomingBoxConsumer)
class MyConsumer(object):
    def __init__(self):
        self.name = 'My Consumer'

    def process(self, item, item_id, encrypted=True):
        cleartext = my_custom_decrypt(item) if encrypted else item
        processed_parts = my_custom_processing(item)
        return defer.succeed(processed_parts)

    def save(self, parts, item_id):
        return defer.gatherResults([db.save(part) for part in parts])
```


Future Features
---------------

Still subject to discussion, but some features that are desired for future iterations are:

* Provide a mechanism to retry documents marked as failed by previous revisions.
* Internalizing public key infrastructure (using ECC).
* ACLs to allow other users to push documents to an user Incoming Box.
* Provide alternative implementations of the Incoming Box endopoint (for example, in Rust)

Writing Data When User Quota is Exceeeded
+++++++++++++++++++++++++++++++++++++++++
* The server SHOULD move the payload to the permanent storage in the user storage space only after checking that the size of the storage currently occupied by the user data, plus the payload size does not exceed the allowed quota, if any, plus a given tolerance limit.
* The Trusted Application SHOULD receive an error message as a response to its storage request, so that it can register the failure to store the data, or inform the sender in the case in which it is acting as a delegate to deliver a message.


LIST QUALIFIERS
+++++++++++++++

In order to improve performance and responsiveness, a list request MAY be
qualified by the following parameters that the server SHOULD satisfy.
The responses are, in any case, a list of the ``uuids`` of the Blobs.

.. note: Should we extend this to other structure? Like a dict, containing
         timestamps and sizes.

- Pagination.
- Skip by SIZE THRESHOLD.
- Include messages with PROCESSING flag.


PAGINATION
~~~~~~~~~~


* ``LIMIT``: number of messages to receive in a single response
* ``PAGE``: when used with limit, which page to return (limited by the number in LIMIT). (Note that, in reality, any client will just process the first page under a normal functioning mode).

Example::

  IncomingBox.list('mx', limit=20, page=1)

SKIP-BY-SIZE
~~~~~~~~~~~~

* SIZE_LIMIT: skips messages bigger than a given size limit, to avoid downloading payloads too big when client is interested in a quick list of incoming messages.

Example::

  IncomingBox.list('mx', size_limit=10MB)
