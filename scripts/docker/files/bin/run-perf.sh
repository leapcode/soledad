#!/bin/bash

REPO=/builds/leap/soledad/testing
COUCH_URL="${COUCH_URL:-http://127.0.0.1:5984}"

if [ ! -z "${SOLEDAD_REMOTE}" ]; then
  git -C ${REPO} remote set-url origin ${SOLEDAD_REMOTE}
  git -C ${REPO} fetch origin
fi

if [ ! -z "${SOLEDAD_BRANCH}" ]; then
  git -C ${REPO} checkout ${SOLEDAD_BRANCH}
fi

cd ${REPO}

tox perf -- \
	--durations 0 \
	--couch-url ${COUCH_URL} \
	--twisted
