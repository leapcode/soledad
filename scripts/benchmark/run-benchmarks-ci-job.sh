#!/bin/sh

# Run benchmakr tests for CI jobs, and optionally compare results with historic
# series.
#
# Usage Example
# -------------
#
# Run this script with the environment name as the only argument:
#
#   ./run-benchmarks-ci-job.sh environment-name
#
# This script is used in .gitlab-ci.yml to run benchmark jobs. It has been
# factored out from that file to avoid bloating it with too much information.
#
# Environment Variables
# ---------------------
#
#   RUN_BENCHMARKS:     If not set, skip this run.
#   CHECK_FOR_OUTLIERS: If set, check if results are outliers.

set -eu
set -o xtrace

ENVIRONMENT=${1}
RUN_BENCHMARKS=${RUN_BENCHMARKS:-}

if [ -z "${RUN_BENCHMARKS}" ]; then
  echo "Skipping benchmarks because RUN_BENCHMARKS is not set..."
  exit 0
fi

echo "Running tox in environment ${ENVIRONMENT}..."

#
# run benchmark tests with tox
#

tempfile=$(mktemp)
/usr/bin/unbuffer \
  tox \
    --recreate \
    -e ${ENVIRONMENT} \
    -- \
    --couch-url http://couchdb:5984 \
    --benchmark-json=${tempfile} \
    -m runme \
  | /usr/bin/ts -s

#
# check results for bad outlier detecion
#

# stop here unless environment starts with "benchmark-"
if [ -z "$(echo ${ENVIRONMENT} | grep ^benchmark-)" ]; then
  exit 0
fi

# stop here unless the CHECK_FOR_OUTLIERS environment variable is set
if [ -z "${CHECK_FOR_OUTLIERS:-}" ]; then
  exit 0
fi

# fail test for bad outliers
echo "Comparing current test results with history..."
basedir=$(dirname "${0}")
${basedir}/compare-results-with-history.py ${tempfile}
