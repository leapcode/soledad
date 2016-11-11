# start with a fresh debian image
FROM debian

# expose soledad server port in case we want to run a server container
EXPOSE 2424

# install dependencies from debian repos
COPY files/apt/leap.list /etc/apt/sources.list.d/

RUN apt-get update
RUN apt-get -y --force-yes install leap-archive-keyring

RUN apt-get update

RUN apt-get -y install git
RUN apt-get -y install vim
RUN apt-get -y install python-ipdb

# install python deps
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

RUN pip install -U pip
RUN pip install psutil

# install soledad-perf deps
RUN pip install klein
RUN apt-get -y install curl
RUN apt-get -y install httperf

# clone repositories
ENV BASEURL "https://github.com/leapcode"
ENV VARDIR "/var/local"
ENV REPOS "soledad leap_pycommon soledad-perf"
RUN for repo in ${REPOS}; do git clone ${BASEURL}/${repo}.git /var/local/${repo}; done

# copy over files to help setup the environment and run soledad
RUN mkdir -p /usr/local/soledad

COPY files/build/install-deps-from-repos.sh /usr/local/soledad/
RUN /usr/local/soledad/install-deps-from-repos.sh

COPY files/bin/ /usr/local/soledad/
