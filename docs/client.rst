.. _soledad-client:

Soledad Client
==============

The Soledad Client is a Python library aimed to provide access to a document
store that can be synchronized securelly with other deviced through the Soledad
Server. Key aspects of Soledad Client include:

  * **Encrypted local storage:** All data cached locally is stored in an
    encrypted database.

  * **Client-side encrypted sync:** Soledad puts very little trust in the
    server by encrypting all data before it is synchronized to the server and
    by limiting ways in which the server can modify the user's data.

  * **Document database:** An application using the Soledad client library is
    presented with a document-centric database API for storage and sync.
    Documents may be indexed, searched, and versioned.

  * **Blobs storage:** The client and server API provide blobs storage, which
    can be used both for data delivery in the server side (i.e. email) and
    payload storage on the client side.

Setting-up
----------

The following information is needed in order to instantiate a soledad client:

  * ``uuid``: the user's uuid.
  * ``passphrase``: the user's passphrase.
  * ``secrets_path``: a local path for secrets storage.
  * ``local_db_path``: a local path for the documents database.
  * ``server_url``: the Soledad Server's URL.
  * ``cert_file``: a local path for the CA certificate.
  * ``auth_token``: an authentication token obtained after logging into the
    provider.

Once all pieces are in place, you can instantiate the client as following:

.. code-block:: python

    from leap.soledad.client import Soledad
    
    client = Soledad(
        uuid,
        passphrase,
        secrets_path=secrets_path,
        local_db_path=local_db_path,
        server_url=server_url,
        cert_file=cert_file,
        auth_token=token)

Usage example
-------------

Soledad is written in the `Twisted asynchronous model
<https://twistedmatrix.com/documents/current/core/howto/defer-intro.html>`_, so
you will need to make sure a `reactor
<http://twistedmatrix.com/documents/current/core/howto/reactor-basics.html>`_
is running.

An example of usage of Soledad Client for creating a document and Creation of
a document and synchronization is done as follows:

.. code-block:: python

    from twisted.internet import defer, reactor
    
    @defer.inlineCallbacks
    def client_usage_example():

        # create a document and sync it with the server
        yield client.create_doc({'my': 'doc'}, doc_id='some-id')
        doc = yield client.get_doc('some-id')
        yield client.sync()
        
        # modify the document and sync again
        doc.content = {'new': 'content'}
        yield client.put_doc(doc)
        yield client.sync()
    
    d = client_usage_example()
    d.addCallback(lambda _: reactor.stop())

    reactor.run()
