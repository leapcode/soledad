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

# parse command
if [ ${#} -ne 1 ]; then
  echo "Usage: ${0} perf|bootstrap"
  exit 1
fi

test=${1}

if [ "${test}" != "perf" -a "${test}" != "bootstrap" ]; then
  echo "Usage: ${0} perf|bootstrap"
  exit 1
fi

# make sure the image is up to date
make image

# get script name and path
script=$(readlink -f "$0")
scriptpath=$(dirname "${script}")

# run the server
tempfile=`mktemp -u`
make run-server CONTAINER_ID_FILE=${tempfile}

# wait for server until timeout
container_id=`cat ${tempfile}`
server_ip=`${scriptpath}/get-container-ip.sh ${container_id}`
start=`date +%s`
elapsed=0

echo "Waiting for soledad server container to come up..."

while [ ${elapsed} -lt ${TIMEOUT} ]; do
  curl -s http://${server_ip}:2424 > /dev/null
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

set -e

# run the test
make run-client-${test} CONTAINER_ID_FILE=${tempfile}
rm -r ${tempfile}
