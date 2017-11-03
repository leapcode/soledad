.. _client-encryption:

Client-side encryption and authentication
=========================================

Before any user data is sent to the server, Soledad Client **symmetrically
encrypts** it using `AES-256
<https://en.wikipedia.org/wiki/Advanced_Encryption_Standard>`_ operating in
`GCM mode <https://en.wikipedia.org/wiki/Galois/Counter_Mode>`_. That mode of
encryption automatically calculates a **Message Authentication Code** (a `MAC
<https://en.wikipedia.org/wiki/Message_authentication_code>`_) during block
encryption, and so gives Soledad the ability to encrypt on the fly while
transmitting data to the server. Similarly, when downloading a symmetrically
encrypted document from the server, Soledad Client will decrypt it and verify
the MAC tag in the end before accepting the document.

The symmetric key used to encrypt a document is derived from the storage secret
and the document id, with HMAC using SHA-256 as a hash function.

MAC verification of JSON documents
----------------------------------

JSON documents are versioned (see :ref:`document-sync`), so in this case the
calculation of the MAC also takes into account the document revision to avoid
tampering. Soledad Client will refuse to accept a document if it does not
include a higher revision. In this way, the server cannot rollback a document
to an older revision. The server also cannot delete a document, since document
deletion is handled by removing the document contents, marking it as deleted,
and incrementing the revision. However, a server can withhold from the client
new documents and new revisions of a document (including withholding document
deletion).

MAC verification of Blobs
-------------------------

Because Blobs are immutable (see :ref:`blobs-sync`), in this case the MAC is
calculated over the content of the blob only (i.e. no metadata is taken into
account). Blob downloads will fail irrecoverably if the client is unable to
verify the MAC after a certain number of retries.

Outsourced encryption by third-party applications
-------------------------------------------------

Soledad Client will allways do **symmetric encryption** with a secret known
only to the client. But data can also be delivered directly to the user's
database in the server by other applications. One example is mail delivery: the
MX application receives a message targetted to a user, encrypts it with the
user's OpenPGP public key and delivers it directly to the user's database in
the server.

Server-side applications can define their own encryption schemes and Soledad
Client will not attempt decryption and verification in those cases.
