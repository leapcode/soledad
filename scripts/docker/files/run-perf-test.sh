#!/bin/sh

# Start a soledad-perf test using a remote server.
#
# The script does the following:
#
#   - configure a remote repository for soledad repo if SOLEDAD_REMOTE is set.
#
#   - checkout a specific branch if SOLEDAD_BRANCH is set.
#
#   - run the soledad-perf local twisted server that runs the client. Note
#     that the actual soledad server should be running on another docker
#     container. This local server is only used to measure responsiveness of
#     soledad client. The script waits for the server to come up before
#     continuing, or else times out after TIMEOUT seconds.
#
#   - trigger the creation of documents for sync.
#
#   - start the measurement of server responsiveness and sync stages.
#
#   - stop the test.
#
# This script is meant to be copied to the docker container and run upon
# container start.

CMD="/usr/local/soledad/test-env.py"
REPO="/var/local/soledad"
TIMEOUT=20

#-----------------------------------------------------------------------------
# configure a remote and checkout a branch
#-----------------------------------------------------------------------------

if [ ! -z "${SOLEDAD_REMOTE}" ]; then
  git -C ${REPO} remote add test ${SOLEDAD_REMOTE}
  git -C ${REPO} fetch test
fi

if [ ! -z "${SOLEDAD_BRANCH}" ]; then
  git -C ${REPO} checkout ${SOLEDAD_BRANCH}
fi

if [ ! -z "${SOLEDAD_PERF_REMOTE}" ]; then
  git -C /var/local/soledad-perf remote add test ${SOLEDAD_PERF_REMOTE}
  git -C /var/local/soledad-perf fetch test
fi

if [ ! -z "${SOLEDAD_PERF_BRANCH}" ]; then
  git -C /var/local/soledad-perf checkout ${SOLEDAD_PERF_BRANCH}
fi

#-----------------------------------------------------------------------------
# write a configuration file for the perf test
#-----------------------------------------------------------------------------

cd /var/local/soledad-perf

cat > defaults.conf <<EOF
[server]
host = ${SOLEDAD_SERVER_URL}

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

#-----------------------------------------------------------------------------
# start the local server and wait for it to come up
#-----------------------------------------------------------------------------

# start local test server on background
make soledad-sync-server | grep -v stats | grep -v ping  &

# wait for server until timeout
start=`date +%s`
elapsed=0

echo "Waiting for perf server to come up..."

while [ ${elapsed} -lt ${TIMEOUT} ]; do
  result=`curl -s http://127.0.0.1:8080/ping`
  if [ ${?} -eq 0 -a "${result}" = "easy!" ]; then
    echo "Perf server (running soledad client) is up!"
    break
  else
    sleep 1
  fi
  now=`date +%s`
  elapsed=`expr ${now} - ${start}`
done

# exit with an error code if timed out waiting for server
if [ ${elapsed} -ge ${TIMEOUT} ]; then
  echo "Error: server unreachable at http://127.0.0.1:8080 after ${TIMEOUT} seconds."
  exit 1
fi

sleep 2

#-----------------------------------------------------------------------------
# create docs and run test
#-----------------------------------------------------------------------------

# create documents in client
make trigger-create-docs

# launch background series measurement
make measure-series > /dev/null &
sleep 5  # wait a bit for some data points

# run a sync and generate a graph
make trigger-sync
make trigger-stop
make graph-image
