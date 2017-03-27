# start with a fresh debian image
# we use backports because of libsqlcipher-dev
FROM debian:jessie-backports

RUN apt-get update

# needed to build python twisted module
RUN apt-get -y install libpython2.7-dev
# needed to build python cryptography module
RUN apt-get -y install libssl-dev
RUN apt-get -y install libffi-dev
# needed to build pysqlcipher
RUN apt-get -y install libsqlcipher-dev
# needed to support keymanager
RUN apt-get -y install libsqlite3-dev

# install pip and tox
RUN apt-get -y install python-pip
# We need git from backports because it has
# the "%cI: committer date, strict ISO 8601 format"
# pretty format which is used by pytest-benchmark
RUN apt-get -y install -t jessie-backports git

# Use use to show connection to couchdb during CI
RUN apt-get -y install curl

RUN pip install -U pip
RUN pip install tox

# clone repositories
RUN mkdir -p /builds/leap
RUN git clone https://0xacab.org/leap/soledad.git /builds/leap/soledad

# use tox to install everything needed to run tests
RUN cd /builds/leap/soledad/testing && tox -v -r --notest

RUN mkdir -p /usr/local/soledad
COPY files/bin/ /usr/local/soledad/
