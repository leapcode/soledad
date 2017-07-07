Benchmark all commits
=====================

The script in this directory is used to run the benchmarking tests for all
commits in the repository.

It is actually not possible to run all benchmarking tests for all commits
because:

  - at some points in the repo history, the tested code didn't exist.

  - at some poitns in the repo history, the teste code might have been
    refactored and the api would not match the one used in tests.

So what this script does is the following:

  - check out .gitlab-ci.yml from current master.
  - use gitlab-runner to exec a build locally.
  - set an environment variable (BENCHMARK_ALL_COMMITS=1)so the build script
    knows that it has to setup the environment.
  - store timestamp and exit status of each run.
  - checkout previous commit and iterate.

How to use the script
---------------------

Once you have gitlab-runner setup in the machine and the elasticsearch
credentials, use the following commands to run the script:

    git clone https://0xacab.org/leap/soledad
    cd soledad/
    export PYTEST_OPTS="--benchmark-autosave --benchmark-storage=\"elasticsearch+https://USER:PASSWORD@moose.leap.se:9200\""
    scripts/benchmark/benchmark-all-commits.sh
