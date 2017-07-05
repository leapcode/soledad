#!/bin/bash -x
#
# Go backwards in git history and run benchmark tests.
#
# Export PYTEST_OPTS so pytest will post metrics to an elasticsearch
# instance, i.e.
#
#     export PYTEST_OPTS='--benchmark-autosave --benchmark-storage="elasticsearch+https://USER:PASSWORD@moose.leap.se:9200"'
#
# or, for testing a single test group:
#
#     export PYTEST_OPTS='--benchmark-autosave --benchmark-storage="elasticsearch+https://USER:PASSWORD@moose.leap.se:9200" -m benchmark_test_instance'
#
# Todo
#
#   - Error handling. This script is dumb and will run forever.

# Too many commits just fail for different reasons,
# so we just benchmark thoses that succeed.
#set -e



#rm -rf testing/.tox

while /bin/true
do

  commit_id=$(git rev-parse HEAD)
  echo -e '\n\n\n\n\n'
  echo -e "\e[34m$(date): Starting benchmarking of commit ${commit_id:0:8}, which is $(git rev-list --count ${commit_id}..origin/master) commits back from master:\e[0m"
  echo
  git show | head -6
  echo

  # Option 1: Run couchdb + tox localy - dirty!
  # curl -s localhost:5984 || exit 1
  # Make sure we kill all leftover soledad server/pytest procs
  #pkill -f -9 tox
  #git checkout origin/master testing/tox.ini testing/tests/benchmarks/conftest.py testing/tests/conftest.py
  #tox -c testing/tox.ini -e benchmark -- -x "$PYTEST_OPTS"
  #git reset HEAD testing/tox.ini
  #git checkout testing/tox.ini testing/tests/benchmarks/conftest.py testing/tests/conftest.py

  # Option 2: Run couchdb + tox in docker container using gitlab-runner
  git checkout origin/benchmark-all-commits .gitlab-ci.yml
  time gitlab-runner exec docker \
    benchmark \
    --timeout 7200 \
    --env PYTEST_OPTS="$PYTEST_OPTS" \
    --env HOST_HOSTNAME="$(hostname)"

  code=$?
  echo "$(date -Iseconds) ${commit_id} ${code}" >> results.txt

  echo
  echo -e "\e[34m$(date): Finished benchmarking of commit ${commit_id:0:8}, which is $(git rev-list --count ${commit_id}..origin/master) commits back from master:\e[0m"
  echo
  git show | head -6
  echo

  # checkout next commit
  git reset --hard HEAD^

  # stop if we reached the first commit in the repo
  if [ $? -ne 0 ]; then
    break
  fi
done
