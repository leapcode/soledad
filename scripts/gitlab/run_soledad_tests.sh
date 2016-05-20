#!/bin/sh


# Name:
#   run_tests.sh -- run soledad tests from a given source directory
#
# Usage:
#   run_tests.sh
#
# Description:
#   This script sets up a minimal test environment from a soledad source
#   directory and runs all tests, returning the same exit status as the test
#   process. As it is intended to be called by a GitLab Runner, it expects the
#   following GitLab CI predefined variable to be set in the environment:
#
#   CI_PROJECT_DIR   The full path where the repository is cloned and where
#                    the build is ran
#
# Example:
#   CI_PROJECT_DIR=/tmp/soledad run_tests.sh


# Fail if expected variable is not a directory.
if [ ! -d "${CI_PROJECT_DIR}" ]; then
  echo "Error! Not a directory: ${CI_PROJECT_DIR}"
  exit 1
fi


# Setup pip to use wheels because it is prebuilt and thus faster to deploy.

PIP_INSTALL="pip install -U                               \
               --find-links=https://lizard.leap.se/wheels \
               --trusted-host lizard.leap.se"


# Use a fresh python virtual envinroment each time.

setup_venv() {
  venv=${1}
  virtualenv ${venv}
  . ${venv}/bin/activate
}


# Most of the dependencies are installed directly from soledad source pip
# requirement files. Some of them need alternative ways of installing because
# of distinct reasons, see below.

install_deps() {
  install_leap_common
  install_scrypt
  install_soledad_deps
}


# Install scrypt manually to avoid import problems as the ones described in
# https://leap.se/code/issues/4948

install_scrypt() {
  pip install scrypt
}


# Iterate through soledad components and use the special pip install script to
# install (mostly) all requirements for testing.
#
# TODO: Soledad tests should depend on almost nothing and have every component
#       from other leap packages mocked.

install_soledad_deps() {
  for pkg in common client server; do
    testing="--testing"
    if [ "${pkg}" = "server" ]; then
      # soledad server doesn't currently have a requirements-testing.pip file,
      # so we don't pass the option when that is the case
      testing=""
    fi
    (cd ${CI_PROJECT_DIR}/${pkg} \
     && ./pkg/pip_install_requirements.sh ${testing} --use-leap-wheels \
     && python setup.py develop)
  done
}


# We have to manually install leap.common from source because:
#
#   - the leap.common package is not currently set as a "testing dependency"
#     for soledad; and
#
#   - having another package from the leap namespace installed from egg or
#     wheels may confuse the python interpreter when importing modules.

install_leap_common() {
  temp=`mktemp -d`
  host="git://github.com/leapcode"
  proj="leap_pycommon"
  git clone ${host}/${proj} ${temp}/${proj}
  (cd ${temp}/${proj} \
   && ./pkg/pip_install_requirements.sh \
   && python setup.py develop)
}


# Run soledad tests. The exit status of the following function is used as the
# script's exit status.

run_tests() {
  trial leap.soledad.common.tests
}


# Cleanup leftovers before finishing.

cleanup_venv() {
  venv=${1}
  rm -rf ${venv}
}


main() {
  venv="`mktemp -d`/venv"
  setup_venv ${venv}
  install_deps
  run_tests
  status=$?
  cleanup_venv ${venv}
  exit ${status}
}


main
