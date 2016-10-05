# start with a fresh debian image
FROM debian:jessie-backports

RUN apt-get update

RUN apt-get -y install git

# needed to build python twisted module
RUN apt-get -y install libpython2.7-dev
# needed to build python cryptography module
RUN apt-get -y install libssl-dev
RUN apt-get -y install libffi-dev
# needed to build pysqlcipher
RUN apt-get -y install libsqlcipher-dev

# install pip and tox
RUN apt-get -y install python-pip
RUN pip install -U pip
RUN pip install tox

# clone repositories
RUN mkdir -p /builds/leap
RUN git clone -b develop https://0xacab.org/leap/soledad.git /builds/leap/soledad

# use tox to install everything needed to run tests
RUN cd /builds/leap/soledad/testing && tox -v -r --notest

RUN mkdir -p /usr/local/soledad
COPY files/bin/ /usr/local/soledad/
