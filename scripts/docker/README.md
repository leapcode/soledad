Soledad Docker Images
=====================

The files in this directory help create a docker image that is usable for
running soledad server and client in an isolated docker context. This is
especially useful for testing purposes as you can limit/reserve a certain
amount of resources for the soledad process, and thus provide a baseline for
comparison of time and resource consumption between distinct runs.

Check the `Dockerfile` for the rules for building the docker image.

Check the `Makefile` for example usage of the files in this directory.


Environment variables for server script
---------------------------------------

If you want to run the image for testing you may pass the following
environment variables for the `files/start-server.sh` script for checking out
a specific branch on the soledad repository:

  SOLEDAD_REMOTE - a git url for a remote repository that is added at run time
                   to the local soledad git repository.

  SOLEDAD_BRANCH - the name of a branch to be checked out from the configured
                   remote repository.

Example:

  docker run leap/soledad:1.0 /usr/local/soledad/start-server.sh
