# start with a fresh debian image
# we use backports because of libsqlcipher-dev
FROM 0xacab.org:4567/leap/docker/debian:jessie_amd64

RUN apt-get update
RUN apt-get -y dist-upgrade

# needed to build python twisted module
RUN apt-get -y install --no-install-recommends libpython2.7-dev \
  # add unbuffer and ts for timestamping
  moreutils expect tcl8.6 \
  # needed to build python cryptography module
  libssl-dev libffi-dev \
  # needed to build pysqlcipher
  libsqlcipher-dev \
  # needed to support keymanager
  libsqlite3-dev \
  # install pip, so later we can install tox
  python-pip \
  # used to show connection to couchdb during CI
  curl \
  # needed to build pysqlcipher module
  build-essential \
  # needed to build docker images
  docker.io \
  # needed to send email during e2e tests
  swaks \
  libnet-dns-perl \
  libnet-ssleay-perl

# We need git from backports because it has
# the "%cI: committer date, strict ISO 8601 format"
# pretty format which is used by pytest-benchmark
RUN apt-get -y install -t jessie-backports git

RUN pip install -U pip
RUN pip install tox
