#!/bin/sh

# This script builds the Soledad documentation using a virtual environment.
# You can pass the target directory as the first command line argument:
#
#   ./build-soledad-doc.sh [target-dir]
#
# If you no directory is passed, documentation will be built on the default
# place used by sphinx: <repodir>/docs/_build

set -eu
set -o xtrace

BUILDDIR=${1:-_build}
REPO="http://0xacab.org/leap/soledad"
REPO=/tmp/soledad
TEMPDIR=$(mktemp -d)
VENVDIR=${TEMPDIR}/venv
REPODIR=${TEMPDIR}/soledad
TARGET=html

if [[ ${BUILDDIR} = /* ]]; then
  type="absolute"
  docdir=${BUILDDIR}/${TARGET}
else
  type="relative"
  docdir=${REPODIR}/docs/${BUILDDIR}/${TARGET}
fi

echo "Documentation will be written to ${type} path ${BUILDDIR}."

# build and activate the virtual environment
if [ ! -d ${VENVDIR} ]; then
  virtualenv ${VENVDIR}
fi
. ${VENVDIR}/bin/activate

# clone the canonical repository
git clone ${REPO} ${REPODIR}

# install deps
pip install -U pip wheel
pip install -r ${REPODIR}/docs/requirements.pip

# build documentation
make -C ${REPODIR}/docs ${TARGET} BUILDDIR=${BUILDDIR}
ls -1 ${docdir}
