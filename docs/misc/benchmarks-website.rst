Benchmarks website
==================

Currently, showing the results of benchmarks still requires manual
intervention. With time, we want to automatize these tasks.

How to add a new test to the benchmarks website
-----------------------------------------------

Current steps are:

#. Create a new test in ``soledad/testing/tests/benchmarks``, and commit.
#. Push it to ``ssh://0xacab.org/leap/soledad``.
#. Wait until benchmarks stage finishes (so results are posted to elasticsearch).
#. Update kibana visualizations and dashboards::

    # currently, kibana configurations are in the `scripts` repository.
    cd scripts/elastic/
    ./generate-config.py
    ./load.sh -url https://moose.leap.se:9200

#. Update the benchmarks website::

    # currently, website lives in the `puppet` repository.
    cd puppet/modules/site_benchmarks/
    vim generate-config
    ./gen-dashboard-pages.sh
    make
    git commit -a -m "[benchmarks] update website with new tests"
    git push

TODO
----

The following steps are needed to have the website be updated automatically
with all existing stats:

- Move kibana-related stuff to the ``puppet`` repository.
- Push kibana-related scripts to the server.
- Have kibana be updated periodically with new tests (either using a cron job
  and maybe also use the CI to trigger that?)
- Modify website generation scripts so they run in the server to generate
  static html (also cron and CI would be great here).
- Enable nginx ssi.
- Modify ``is-master-benchmarked.sh`` script to generate a simple html, include
  the generated html in benchmark website.
