#!/bin/bash

REPO=/builds/leap/soledad/testing

if [ ! -z "${SOLEDAD_REMOTE}" ]; then
  git -C ${REPO} remote set-url origin ${SOLEDAD_REMOTE}
  git -C ${REPO} fetch origin
fi

if [ ! -z "${SOLEDAD_BRANCH}" ]; then
  git -C ${REPO} checkout ${SOLEDAD_BRANCH}
fi

(cd ${REPO}; tox -- -v --durations 0 --couch-url http://couchdb:5984)
