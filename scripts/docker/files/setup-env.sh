#!/bin/bash

# Clone soledad repository and install soledad dependencies needed to run
# client and server in a test environment.
#
# This script is meant to be copied to the docker container and run after
# system dependencies have been installed.

BASEDIR="/var/local"
BASEURL="https://github.com/leapcode"

mkdir -p ${BASEDIR}

# clone repositories
repos="soledad leap_pycommon soledad-perf"

for repo in ${repos}; do
  repodir=${BASEDIR}/${repo}
  if [ ! -d ${repodir} ]; then
    git clone ${BASEURL}/${repo} ${repodir}
    git -C ${repodir} fetch origin
  fi
done

# use latest pip because the version available in debian jessie doesn't
# support wheels
pip install -U pip

pip install psutil

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
