#!/bin/sh

# make sure that the current installed version of pysqlcipher has the
# HAVE_USLEEP flag set so we don't have problems with concurrent db access.

set -e

install_bundled_pysqlcipher() {
  pip uninstall -y pysqlcipher
  pip install --install-option="--bundled" pysqlcipher
}

./check-pysqlcipher.py || (install_bundled_pysqlcipher && ./check-pysqlcipher.py)
