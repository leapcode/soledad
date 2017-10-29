Blobs Server Scalability Tests
==============================

This folder contains code for running benchmark tests for determining Soledad
Server Blobs service scalability. This consists basically in launching a number
of parallel blobs upload or download requests, to assess the number of requests
per second that the server is able to answer. 

When analyzing results, it's important to have in mind that the size of the
blobs that are transferred as well as the bandwith of both the server and the
client used for the test are resources that have high impact in the results.

Test Controller server
----------------------

In the server, run the following to have an instance of the Test Controller
server running:

  make install-server
  make start-server

And, if you want to see the logs, use:

  make log 

Alternativelly, use `make start-server-nodaemon` to avoid detaching from the
terminal.

Test Controller client
----------------------

Make sure an instance of the Test Controller Server is reachable at $(URI),
and run:

  make install-client
  make run-test
