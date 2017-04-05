#!/bin/bash -x
#
# Go backwards in git history and run benchmark tests
# Export PYTEST_OPTS so pytest will post metrics to an elasticsearch
# instance, i.e.
#
#     export PYTEST_OPTS='--benchmark-autosave --benchmark-storage="elasticsearch+https://USER:PASSWORD@moose.leap.se:9200"'
# or, for testing a single test group:
#     export PYTEST_OPTS='--benchmark-autosave --benchmark-storage="elasticsearch+https://USER:PASSWORD@moose.leap.se:9200" -m benchmark_test_instance'
#
# Todo
#
#   - Error handling. This script is dump and will run forever.

#rm -rf testing/.tox

while /bin/true
do
  echo -e '\n\n\n\n\n'

  git checkout origin/master testing/tox.ini testing/tests/benchmarks/conftest.py testing/tests/conftest.py

  curl -s localhost:5984 || exit 1

  # Make sure we kill all leftover soledad server/pytest procs
  pkill -f -9 tox
  tox -c testing/tox.ini -e benchmark -- -x "$PYTEST_OPTS"
  #gitlab-runner exec docker benchmark --env PYTEST_OPTS="$PYTEST_OPTS"


  git reset HEAD testing/tox.ini
  git checkout testing/tox.ini testing/tests/benchmarks/conftest.py testing/tests/conftest.py
  git checkout HEAD^
done
