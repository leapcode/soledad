#!/bin/sh

configure_soledad_repos() {
  if [ ! -z "${SOLEDAD_REMOTE}" ]; then
    git -C ${REPO} remote set-url origin ${SOLEDAD_REMOTE}
    git -C ${REPO} fetch origin
  fi

  if [ ! -z "${SOLEDAD_BRANCH}" ]; then
    git -C ${REPO} checkout ${SOLEDAD_BRANCH}
  fi
}
