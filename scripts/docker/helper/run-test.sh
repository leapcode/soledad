#!/bin/sh

# Run 2 docker images, one with soledad server and another with a soledad
# client running a test.
#
# As there are many possible, tests, you have to pass an argument to the
# script saying which test you want to run. Currently, possible values are
# "connect" and "perf".
#
# After launching the server container, the script waits for TIMEOUT seconds
# for it to come up. If we fail to detect the server, the script exits with
# nonzero status.

# seconds to wait before giving up waiting from server
TIMEOUT=20

# get a test
if [ ${#} -ne 1 ]; then
  "Usage: ${0} [perf|connect]"
  exit 1
fi

TEST=${1}

# get script name and path
SCRIPT=$(readlink -f "$0")
SCRIPTPATH=$(dirname "$SCRIPT")

# run the server
tempfile=`mktemp -u`
make run-server CONTAINER_ID_FILE=${tempfile}

# get server container info
container_id=`cat ${tempfile}`
server_ip=`${SCRIPTPATH}/get-container-ip.sh ${container_id}`

# wait for server until timeout
start=`date +%s`
elapsed=0

echo "Waiting for soledad server container to come up..."

while [ ${elapsed} -lt ${TIMEOUT} ]; do
  result=`curl -s http://${server_ip}:2424`
  if [ ${?} -eq 0 ]; then
    echo "Soledad server container is up!"
    break
  else
    sleep 1
  fi
  now=`date +%s`
  elapsed=`expr ${now} - ${start}`
done

# exit with an error code if timed out waiting for server
if [ ${elapsed} -ge ${TIMEOUT} ]; then
  echo "Error: server unreachable at ${server_ip} after ${TIMEOUT} seconds."
  exit 1
fi

# run the client
if [ "${TEST}" = "connect" ]; then
  make run-client-test CONTAINER_ID_FILE=${tempfile}
elif [ "${TEST}" = "perf" ]; then
  make run-perf-test CONTAINER_ID_FILE=${tempfile}
  make cp-perf-result CONTAINER_ID_FILE=${tempfile}
fi
