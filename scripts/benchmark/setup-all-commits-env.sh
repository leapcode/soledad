#!/bin/sh

# This script is supposed to be called while running the benchmark job defined
# in `/.gitlab-ci.yml`, to setup the environment when benchmarking all commits
# back in time. It will checkout some needed files and do whatever is needed to
# run tests from older versions of the repository with the newest benchmarking
# facilities.

set -e

# By default, gitlab-runner will checkout in a detached HEAD (see
# https://gitlab.com/gitlab-org/gitlab-ce/issues/19421) We want
# pytest-benchmark to report the proper branch name, so we make sure we stay at
# the current branch.

# Variable names have changed in latest version of gitlab, but the doc seems to
# be outdated (see also https://docs.gitlab.com/ce/ci/variables/README.html).

# Old variable names:
#git checkout -B "$CI_BUILD_RF_NAME" "$CI_BUILD_REF"

# New (expected) variable names:
#git checkout -B "$CI_COMMIT_REF_NAME" "$CI_COMMIT_SHA"

# Working variable names:
git checkout -B "$CI_COMMIT_REF_NAME" "$CI_COMMIT_REF"

# Gitlab will checkout current revision as master / origin/master
# We need some files from the "furure" in order to post the right
# benchmarking data to elasticsearch.
git remote add leap https://leap.se/git/soledad
git fetch leap
git checkout leap/master \
    testing/tox.ini \
    testing/tests/benchmarks/conftest.py \
    testing/tests/conftest.py \
    testing/check-pysqlcipher.py \
    scripts/benchmark/tune-adbapi-parameters.sh

# ensure larger timeout and more retries for async/concurrent sqlcipher access
./scripts/benchmark/tune-adbapi-parameters.sh
git status
git show -s --pretty=fuller
