#!/bin/bash

# Run a Soledad client connection test.
#
# This script is meant to be copied to the docker container and run upon
# container start.

CMD="/usr/local/soledad/test-env.py"
REPO="/var/local/soledad"

if [ ! -z "${SOLEDAD_REMOTE}" ]; then
  git -C ${REPO} remote set-url origin ${SOLEDAD_REMOTE}
  git -C ${REPO} fetch origin
fi

if [ ! -z "${SOLEDAD_BRANCH}" ]; then
  git -C ${REPO} checkout ${SOLEDAD_BRANCH}
fi

${CMD} soledad-client test --server-url ${SOLEDAD_SERVER_URL}
