#!/bin/sh

# This script is used in .gitlab-ci.yml to run benchmark jobs. It has been
# factored out from that file to avoid bloating it with too much information.
#
# The benchmark job will be skiped if the RUN_BENCHMARKS variable is not set,
# thus allowing for opting in to benchmarking.
#
# This is an attempt to make life of developers easier, by diminishing the time
# of the pipeline by not running benchmarks by default. The canonical repo
# (i.e. https://0xacab.org/leap/soledad) should have the RUN_BENCHMARKS
# variable set to ensure that these jobs will run. Developers can add or remove
# the variable from their environments as they see fit.

set -eu
set -o xtrace

ENVIRONMENT=${1}
RUN_BENCHMARKS=${RUN_BENCHMARKS:-}

if [ -z "${RUN_BENCHMARKS}" ]; then
  echo "Skipping benchmarks because RUN_BENCHMARKS is not set..."
  exit 0
fi

echo "Running tox in environment ${ENVIRONMENT}..."

/usr/bin/unbuffer \
  tox \
    --recreate \
    -e ${ENVIRONMENT} \
    -- \
    --couch-url http://couchdb:5984 \
  | /usr/bin/ts -s
