#!/bin/sh

FILE=client/src/leap/soledad/client/adbapi.py

if [ ! -f ${FILE} ]; then
  exit 0
fi

sed -i -e "s/\(SQLCIPHER_MAX_RETRIES\) =.*/\1 = 100/" ${FILE}
sed -i -e "s/\(SQLCIPHER_CONNECTION_TIMEOUT\) =.*/\1 = 100/" ${FILE}
