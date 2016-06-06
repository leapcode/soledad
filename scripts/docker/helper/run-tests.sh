#!/bin/sh

# Run 2 docker images, one with soledad server and another with a soledad
# client running the tests.
#
# After launching the server, the script waits for TIMEOUT seconds for it to
# come up. If we fail to detect the server, the script exits with nonzero
# status.


# seconds to wait before giving up waiting from server
TIMEOUT=20

# some info from this script
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

while [ ${elapsed} -lt ${TIMEOUT} ]; do
  result=`curl http://${server_ip}:2424`
  if [ ${?} -eq 0 ]; then
    break
  else
    sleep 1
  fi
  now=`date +%s`
  elapsed=`expr ${now} - ${start}`
done

# exit with an error code if timed out waiting for server
if [ ${elapsed} -ge ${TIMEOUT} ]; then
  echo "Error: server unreacheble at ${server_ip} after ${TIMEOUT} seconds."
  exit 1
fi

# run the client
make run-client-test CONTAINER_ID_FILE=${tempfile}
