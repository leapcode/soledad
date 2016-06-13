#!/bin/bash

# Run Soledad trial tests in a docker container created by gitlab-ci.
#
# Gitlab-ci will copy the current test code into /builds/leap/soledad, so this
# script has to uninstall currently installed soledad packages and re-install
# from that location instead.
#
# This script is meant to be copied to the docker container and run upon
# container start.

CMD="/usr/local/soledad/setup-test-env.py"
BASEDIR="/builds/leap/soledad"


install_deps() {
  # ensure all dependencies are installed
  for pkg in common client server; do
    testing="--testing"
    if [ "${pkg}" = "server" ]; then
      # soledad server doesn't currently have a requirements-testing.pip file,
      # so we don't pass the option when that is the case
      testing=""
    fi
    pip uninstall leap.soledad.${pkg}
    (cd ${BASEDIR}/${pkg} \
     && ./pkg/pip_install_requirements.sh ${testing} --use-leap-wheels \
     && python setup.py develop)
  done
}


start_couch() {
  # currently soledad trial tests need a running couch on environment
  ${CMD} couch start
}


run_tests() {
  trial leap.soledad.common
}


main() {
  install_deps
  start_couch
  run_tests
}

main
