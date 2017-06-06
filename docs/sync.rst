Soledad sync process
====================

TODO: this documentation needs to be updated to account for new streaming encryption method.

Phases of sync:

1. client acquires knowledge about server state.
2. client sends its documents to the server.
3. client downloads documents from the server.
4. client records its new state on the server.

Originally in u1db:

* **1** is a GET,
* **2** and **3** are one POST (send in body, receive in response),
* **4** is a PUT.

In soledad:

* **1** is a GET.
* **2** is either 1 or a series of sequential POSTS.
    * **2.1** encrypt asynchronously
    * **2.2** store in temp sync db
    * **2.3** upload sequentially
* **3** is a series of concurrent POSTS, insert sequentially on local client db.
    * **3.1** download concurrently
    * **3.2** store in temp sync db
    * **3.3** decrypt asynchronously
    * **3.4** insert sequentially in local client db
* **4** is a PUT.

This difference between u1db and soledad was made in order to be able to gracefully interrupt the sync in the middle of the upload or the download.

it is essential that all the uploads and downloads are sequential: documents must be added in order. the download happens in parallel, but then locally they are added sequentially to the local db.
