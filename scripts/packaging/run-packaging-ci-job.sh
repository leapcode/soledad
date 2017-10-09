#!/bin/sh

set -eu

echo "Starting packaging script for architecture ${ARCH}, distribution ${DIST}..."

# checkout the relevant branch
if [ -z "$(git remote | grep upstream)" ]; then
  git remote add upstream https://0xacab.org/leap/soledad;
fi

git fetch --tags upstream
pwd; git describe
build-build-package

# test the package with lintian
build-test-lintian

# maybe upload the package
if [ -n "${SSH_PRIVATE_KEY}" ]; then
  upload-package;
else
  echo "Skipping package upload because SSH_PRIVATE_KEY is not set.";
fi

echo "Packaging script finished."
