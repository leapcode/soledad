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
#   RUN_BENCHMARKS          - If not set, skip this run.
#   STATUS_CODE_IF_OUTLIERS - Exit with this status code if outliers are detected.

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
  | /usr/bin/ts -s

#
# check results for bad outlier detecion
#

# stop here unless environment starts with "benchmark-"
if [ -z "$(echo ${ENVIRONMENT} | grep ^benchmark-)" ]; then
  exit 0
fi

# check for bad outliers
basedir=$(dirname "${0}")
${basedir}/check-for-outliers.py --status-code ${STATUS_CODE_IF_OUTLIERS:-0} ${tempfile} 
