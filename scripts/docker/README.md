Soledad Docker Images
=====================

The files in this directory help create a docker image that is usable for
running soledad server and client in an isolated docker context. This is
especially useful for testing purposes as you can limit/reserve a certain
amount of resources for the soledad process, and thus provide a baseline for
comparison of time and resource consumption between distinct runs.

Check the `Dockerfile` for the steps for creating the docker image.

Check the `Makefile` for the rules for running containers.


Installation
------------

1. Install docker for your system: https://docs.docker.com/
2. Build images by running `make`
3. Execute `make run-tox` and `make run-perf` to run tox tests and perf tests,
   respectivelly.
4. You may want to pass some variables to the `make` command to control
   parameters of execution, for example:

      make run-perf SOLEDAD_PRELOAD_NUM=500

   See more variables below.


Environment variables for docker containers
-------------------------------------------

Different environment variables can be set for docker containers and will
cause the scripts to behave differently:

  SOLEDAD_REMOTE - a git url for a remote repository that is added at run time
                   to the local soledad git repository.

  SOLEDAD_BRANCH - the name of a branch to be checked out from the configured
                   remote repository.

  SOLEDAD_PRELOAD_NUM - The number of documents to be preloaded in the
                        container database (either client or server).

  SOLEDAD_PRELOAD_SIZE - The size of the payload of the documents to be
                         prelaoded in the container database (either client or
                         server).

  SOLEDAD_SERVER_URL - The URL of the soledad server to be used during the
                       test.

Check the Makefile for examples on how to use these and maybe even other
variables not documented here.


Communication between client and server containers
--------------------------------------------------

A CONTAINER_ID_FILE variable can be passed to the Makefile target so that the
container id is recorded in a file for further use. This makes it possible to
extract a container's IP and pass it to another container so they can
communicate.
