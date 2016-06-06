#!/bin/sh

tempfile=`mktemp -u`
make run-server CONTAINER_ID_FILE=${tempfile}
sleep 5
make run-client-test CONTAINER_ID_FILE=${tempfile}
