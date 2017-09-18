#!/bin/sh

set -e

if [ -z "${LEAP_CODE_O_MATIC_PRIVATE_TOKEN}" ]; then
  echo "Can't proceed without LEAP_CODE_O_MATIC_PRIVATE_TOKEN variable set."
  exit 1
fi

PIPELINE_URL="https://0xacab.org/api/v4/projects/519/pipelines"
TOKEN_HEADER="PRIVATE-TOKEN: ${LEAP_CODE_O_MATIC_PRIVATE_TOKEN}"
PYTHON_CMD="import sys, json; print json.load(sys.stdin)[1]['sha']"

RESPONSE=$(curl -f -s --header "${TOKEN_HEADER}" ${PIPELINE_URL})
LAST_COMMIT=$(echo "${RESPONSE}" | python -c "${PYTHON_CMD}")

if [ -z "${LAST_COMMIT}" ]; then
  echo "Can't proceed without LAST_COMMIT variable set."
  exit 1
fi

if git diff "${LAST_COMMIT}" HEAD --name-only | grep scripts/docker; then
  docker --version
  docker info
  docker login -u gitlab-ci-token -e sysdev@leap.se -p "${CI_JOB_TOKEN}" "${CI_REGISTRY}"
  docker build -t "${CI_REGISTRY_IMAGE}:latest" scripts/docker
  docker push "${CI_REGISTRY_IMAGE}":latest
fi
