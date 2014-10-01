#!/bin/bash

if [ $# -ne 2 ]; then
  echo "Usage: ${0} <target_address> <number_of_messages>"
  exit 1
fi

target_address=${1}
missing=${2}
echo "Will send ${missing} messages to ${target_address}..."

while [[ ${success} -eq 0 && ${missing} -gt 0 ]]; do
  echo "  missing: ${missing}"
  swaks -S                       \
    -f ${target_address}         \
    -t ${target_address}         \
    -s chipmonk.cdev.bitmask.net \
    -tlsc
  if [ $? -eq 0 ]; then
    missing=`expr ${missing} - 1`
  else
    echo "  error, retrying..."
  fi
done
