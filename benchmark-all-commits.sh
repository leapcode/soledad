#!/bin/sh -x
#
# Go backwards in git history and run benchmark tests
# Export PYTEST_OPTS so pytest will post metrics to an elasticsearch
# instance, i.e.
#
#     export PYTEST_OPTS='--benchmark-autosave --benchmark-storage="elasticsearch+https://USER:PASSWORD@moose.leap.se:9200"'

# Todo
#
#   - Error handling. This script is dump and will run forever.

rm -rf testing/.tox

while /bin/true
do
  git checkout HEAD testing/tox.ini testing/tests/benchmarks/conftest.py testing/tests/conftest.py

  tox -c testing/tox.ini -e benchmark -- -x $PYTEST_OPTS

  git reset HEAD testing/tox.ini
  git checkout testing/tox.ini
  git checkout HEAD^
done
