Ploggin Legacy vs Blobs results
===============================

This script produces a bar graph comparing different implementations of the
mail pipeline (legacy, blobs, blobs with session cache, blobs with session
cache and persistent http connections) for different amount/sizes of incoming
data (1 x 10M, 10 x 1M, 100 x 100K, 1000 x 10K).

Data acquisition
----------------

Data was gathered through different runs of the code in
`soledad/tests/benchmarks/test_legacy_vs_blobs.py`. As these tests are skipped
by default, you have to (1) remove the @pytest.mark.skip decorator and (2)
remove the second call to pytest in `tox.ini` that would cause a second run of
the tests for measuring memory. This script only plots time, for now.

Once you done the above, chdir into `soledad/tests` and do something like this,
for each test group:

  tox -e benchmarks -- -m benchmark_test_legacy_vs_blobs_10_1000k --benchmark-autosave

Each run of tox as above produces a JSON file in `soledad/tests/.benchmarks`
with stats. Each file has to be copied in a subdirectory of the `data/`
directory of the folder where this script lies. Code has to be adapted for each
extra set of results added to the `data/` directory.

Currently, we are comparing 4 implementation variations:

  - data/no-cache: contains legacy as baseline and blobs as the current master
    implementation of blobs.
  - data/cache: adds twisted session cache to blobs connections.
  - data/persistent: adds session cache and persistent HTTP connections.

Plotting
--------

Once you have all your data in subdirectories of the `data/` directory and the
script is correctly tuned for your data, running `make` should be enough to
create a virtualenvironment with dependencies and plotting data.

By default, the script will generate a file called `./legacy-vs-blobs.png` in
the current directory with the plot of the data.
