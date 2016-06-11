#!/bin/sh

# Start a soledad server inside a docker container.
#
# This script will:
#
#   - eventually checkout a specific branch from a specific soledad remote.
#
#   - create everything a soledad server needs to run (certificate, backend
#     server database, tables, etc.
#
#   - eventually preload the server database with a number of documents equal
#     to SOLEDAD_PRELOAD_NUM, and with payload size equal to
#     SOLEDAD_PRELOAD_SIZE.
#
#   - run the soledad server.
#
# This script is meant to be copied to the docker container and run upon
# container start.

CMD="/usr/local/soledad/setup-test-env.py"

#---------------------------------------------------------------------------
# eventually checkout a specific branch from a specific remote
#---------------------------------------------------------------------------

REPO="/var/local/soledad"

if [ ! -z "${SOLEDAD_REMOTE}" ]; then
  git -C ${REPO} remote set-url origin ${SOLEDAD_REMOTE}
  git -C ${REPO} fetch origin
fi

if [ ! -z "${SOLEDAD_BRANCH}" ]; then
  git -C ${REPO} checkout ${SOLEDAD_BRANCH}
fi

#---------------------------------------------------------------------------
# setup environment for running soledad server
#---------------------------------------------------------------------------

${CMD} couch start
${CMD} user-db create
${CMD} token-db create
${CMD} token-db insert-token
${CMD} shared-db create
${CMD} cert create

#---------------------------------------------------------------------------
# write a configuration file for the perf test
#---------------------------------------------------------------------------

if [ "${SOLEDAD_PRELOAD_NUM}" -gt 0 ]; then
  cd /var/local/soledad-perf

  cat > defaults.conf <<EOF
[server]
host = http://127.0.0.1:2424

[client]
uuid = 1234567890abcdef
basedir = /tmp/soledad_client_test
passphrase = 12345678

[sync]
num_docs = ${SOLEDAD_PRELOAD_NUM}
payload = /tmp/payload
payload_size = ${SOLEDAD_PRELOAD_SIZE}
auth_token = an-auth-token

[test]
stats_file = ./out/stats.json
EOF

  echo "Preloading server database..."
  ./scripts/preload_server_database.py
fi

#---------------------------------------------------------------------------
# actually run the server
#---------------------------------------------------------------------------

if [ "${1}" = "--drop-to-shell" ]; then
  /bin/bash
  exit 0
fi

echo "Starting soledad server..."
${CMD} soledad-server start --no-daemonize
