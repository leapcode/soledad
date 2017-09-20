#!/bin/sh

# make sure that the current installed version of pysqlcipher has the
# HAVE_USLEEP flag set so we don't have problems with concurrent db access.

set -e

install_bundled_pysqlcipher() {
  pip uninstall -y pysqlcipher
  pip install --install-option="--bundled" pysqlcipher
}
check_pysqlcipher() {
    SCRIPTPATH=$( cd $(dirname $0) ; pwd -P )
    $SCRIPTPATH/check-pysqlcipher.py
}
check_pysqlcipher || (install_bundled_pysqlcipher && check_pysqlcipher)
