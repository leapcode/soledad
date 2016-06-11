#!/bin/sh

status=0
runs=10

while [ ${status} -eq 0 -a ${runs} -gt 0 ]; do
  echo "=== RUN ${runs}"
  make rm-all-containers
  make run-perf-test
  status=${?}
  runs=`expr ${runs} - 1`
done
