#!/bin/bash

# Run Soledad trial tests.
#
# This script is meant to be copied to the docker container and run upon
# container start.

CMD="/usr/local/soledad/test-env.py"
REPO="/var/local/soledad"

if [ ! -z "${SOLEDAD_REMOTE}" ]; then
  git -C ${REPO} remote add test ${SOLEDAD_REMOTE}
  git -C ${REPO} fetch test
fi

if [ ! -z "${SOLEDAD_BRANCH}" ]; then
  git -C ${REPO} checkout ${SOLEDAD_BRANCH}
fi

# currently soledad trial tests need a running couch on environment
${CMD} couch start

trial leap.soledad.common
