Plotting SQLite Blobs Backend storage/retrieval speed
=====================================================

This script produces a bar graph comparing storage and retrieval times for
different amount/sizes of incoming data (1 x 10M, 10 x 1M, 100 x 100K, 1000
x 10K).

Data acquisition
----------------

Data was gathered through different runs of the code in
`soledad/tests/benchmarks/test_sqlite_blobs_backend.py`. As these tests are run
twice by default, you should remove the second call to pytest in `tox.ini` that
would cause a second run of the tests for measuring memory. This script only
plots time, for now.

Once you done the above, do the following to benchmark and generate data:
```bash
  chdir soledad/tests
  tox -e benchmark -- -m sqlite_blobs_backend_get --benchmark-autosave
  tox -e benchmark -- -m sqlite_blobs_backend_put --benchmark-autosave
```

Each run of tox as above produces a JSON file in `soledad/tests/.benchmarks`
with stats. Copy the first file into `data/get.json` and the second file into
`data/put.json` (where `data/` is a subdir in the same directory of this readme
file).

Plotting
--------

Once you have all your data in subdirectories of the `data/` directory and the
script is correctly tuned for your data, running `make` should be enough to
create a virtualenvironment with dependencies and plotting data.

By default, the script will generate a file called `./sqlite-blobs-backend.png`
in the current directory with the plot of the data.
