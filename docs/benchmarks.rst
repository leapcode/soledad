Benchmarks
==========

Soledad has a set of benchmark tests to assess the time and resources taken by
various tasks. 

Results of benchmarking can be seen in https://benchmarks.leap.se/.

Sync size statistics
--------------------

Currenly, the main use of Soledad is to synchronize client-encrypted email
data. Because of that, it makes sense to measure the time and resources taken
to synchronize an amount of data that is realistically comparable to a user's
email box.

In order to determine what is a good example of dataset for synchronization
tests, we used the size of messages of one week of incoming and outgoing email
flow of a friendly provider. The statistics that came out from that are (all
sizes are in KB):

+--------+-----------+-----------+
|        | outgoing  | incoming  |
+========+===========+===========+
| min    | 0.675     | 0.461     |
+--------+-----------+-----------+
| max    | 25531.361 | 25571.748 |
+--------+-----------+-----------+
| mean   | 252.411   | 110.626   |
+--------+-----------+-----------+
| median | 5.320     | 14.974    |
+--------+-----------+-----------+
| mode   | 1.404     | 1.411     |
+--------+-----------+-----------+
| stddev | 1376.930  | 732.933   |
+--------+-----------+-----------+

Test scenarios
--------------

Ideally, we would want to run tests for a big data set, but that may be
infeasible given time and resource limitations. Because of that, we choose a
smaller data set and suppose that the behaviour is somewhat linear to get an
idea for larger sets.

Supposing a data set size of 10MB, some possibilities for number of documents
and document sizes for testing download and upload are:

* 10 x 1M
* 20 x 500K
* 100 x 100K
* 200 x 50K
* 1000 x 10K

The above scenarios all have documents of the same size. If we want to account
for some variability on document sizes, it is sufficient to come up with a
simple scenario where the average, minimum and maximum sizes are somehow
coherent with the above statistics, like the following one:

* 60 x 15KB + 1 x 1MB
