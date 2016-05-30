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

# copy over files to help setup the environment and run soledad
RUN mkdir -p /usr/local/soledad
RUN mkdir -p /usr/local/soledad/conf

COPY files/setup-env.sh /usr/local/soledad/
COPY files/test-env.py /usr/local/soledad/
COPY files/start-server.sh /usr/local/soledad/
COPY files/conf/* /usr/local/soledad/conf/

# clone repos and install dependencies from leap wheels using pip
RUN /usr/local/soledad/setup-env.sh
