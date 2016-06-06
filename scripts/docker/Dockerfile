# start with a fresh debian image
FROM debian

# expose soledad server port in case we want to run a server container
EXPOSE 2424

# install dependencies from debian repos
COPY files/leap.list /etc/apt/sources.list.d/

RUN apt-get update
RUN apt-get -y --force-yes install leap-archive-keyring

RUN apt-get update
RUN apt-get -y install git
RUN apt-get -y install libpython2.7-dev
RUN apt-get -y install libffi-dev
RUN apt-get -y install libssl-dev
RUN apt-get -y install libzmq3-dev
RUN apt-get -y install python-pip
RUN apt-get -y install couchdb
RUN apt-get -y install python-srp
RUN apt-get -y install python-scrypt
RUN apt-get -y install leap-keymanager
RUN apt-get -y install python-tz
RUN apt-get -y install curl
RUN apt-get -y install python-ipdb

# copy over files to help setup the environment and run soledad
RUN mkdir -p /usr/local/soledad
RUN mkdir -p /usr/local/soledad/conf

# setup the enviroment for running soledad client and server
COPY files/setup-env.sh /usr/local/soledad/
RUN /usr/local/soledad/setup-env.sh

# copy runtime files for running server, client, tests, etc on a container
COPY files/test-env.py /usr/local/soledad/
COPY files/client_side_db.py /usr/local/soledad/
COPY files/util.py /usr/local/soledad/
COPY files/start-server.sh /usr/local/soledad/
COPY files/start-client-test.sh /usr/local/soledad/
COPY files/start-trial-test.sh /usr/local/soledad/
COPY files/conf/* /usr/local/soledad/conf/
