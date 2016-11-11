#!/bin/bash

# Install dependencies needed to run client and server in a test environment.
#
# In details, this script does the following:
#
#   - install dependencies for packages in /var/local from their requirements
#     files in each of the repositories, using python wheels when possible.
#
#   - install the python packages in development mode
#
# This script is meant to be copied to the docker container during container
# build and run after system dependencies have been installed.

BASEDIR="/var/local"

# install dependencies and packages
install_script="pkg/pip_install_requirements.sh"
opts="--use-leap-wheels"
pkgs="leap_pycommon soledad/common soledad/client soledad/server"

for pkg in ${pkgs}; do
  pkgdir=${BASEDIR}/${pkg}
  testing=""
  if [ -f ${pkgdir}/pkg/requirements-testing.pip ]; then
    testing="--testing"
  fi
  (cd ${pkgdir} && ${install_script} ${testing} ${opts})
  (cd ${pkgdir} && python setup.py develop)
done
