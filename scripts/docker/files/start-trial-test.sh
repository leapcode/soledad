#!/bin/bash

# Run Soledad tests.

CMD="/usr/local/soledad/test-env.py"
REPO="/var/local/soledad"

if [ ! -z "${SOLEDAD_REMOTE}" ]; then
  git -C ${REPO} remote add test ${SOLEDAD_REMOTE}
  git -C ${REPO} fetch test
fi

if [ ! -z "${SOLEDAD_BRANCH}" ]; then
  git -C ${REPO} checkout ${SOLEDAD_BRANCH}
fi

${CMD} couch start

trial leap.soledad.common
