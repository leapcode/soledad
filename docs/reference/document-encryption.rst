.. _document-encryption:

Document encryption
===================

Before a JSON document is sent to the server, Soledad Client symmetrically
encrypts it using AES-256 operating in GCM mode. That mode of encryption
automatically calculates a MAC during block encryption, and so gives Soledad
the ability to encrypt on the fly while transmitting data to the server.
Similarly, when downloading a symmetrically encrypted document from the server,
Soledad Client will decrypt it and verify the MAC tag in the end before
accepting the document.

Soledad Client will allways do *symmetric encryption*. Server-side applications
can define their own encryption schemes and Soledad Client will not try to
decrypt in those cases. The symmetric key used to encrypt a document is derived
from the storage secret and the document id, with HMAC using SHA-256 as a hash
function.

The calculation of the MAC also takes into account the document revision to
avoid tampering. Soledad Client will refuse to accept a document if it does not
include a higher revision. In this way, the server cannot rollback a document
to an older revision. The server also cannot delete a document, since document
deletion is handled by removing the document contents, marking it as deleted,
and incrementing the revision. However, a server can withhold from the client
new documents and new revisions of a document (including withholding document
deletion).
