#/usr/bin/env

# This makefile is intended to aid on running soledad docker images for
# specific purposes, as running a server, a client or tests.
#
# In order to communicate the IP address of one container to another, we make
# use of a file containing the container id. You have to explicitelly pass the
# CONTAINER_ID_FILE variable when invoking some of the targets below.
#
# Example usage:
#
#   make run-server CONTAINER_ID_FILE=/tmp/container-id.txt
#   make run-client-perf CONTAINER_ID_FILE=/tmp/container-id.txt

#####################################################################
# Some configurations you might override when calling this makefile #
#####################################################################

IMAGE_NAME           ?= leap/soledad:1.0
SOLEDAD_REMOTE       ?= https://0xacab.org/leap/soledad.git
SOLEDAD_BRANCH       ?= develop
SOLEDAD_PRELOAD_NUM  ?= 100
SOLEDAD_PRELOAD_SIZE ?= 500
MEMORY               ?= 512m

##############################################
# Docker image generation (main make target) #
##############################################

all: soledad-image couchdb-image

soledad-image:
	docker build -t $(IMAGE_NAME) .

couchdb-image:
	(cd couchdb/ && make)

##################################################
# Run a Soledad Server inside a docker container #
##################################################

run-server:
	@if [ -z "$(CONTAINER_ID_FILE)" ]; then \
	  echo "Error: you have to pass a value to CONTAINER_ID_FILE."; \
	  exit 2; \
	fi
	docker run \
	  --memory="$(MEMORY)" \
	  --cpuset-cpus=0 \
	  --env="SOLEDAD_REMOTE=$(SOLEDAD_REMOTE)" \
	  --env="SOLEDAD_BRANCH=$(SOLEDAD_BRANCH)" \
	  --env="SOLEDAD_PRELOAD_NUM=$(SOLEDAD_PRELOAD_NUM)" \
	  --env="SOLEDAD_PRELOAD_SIZE=$(SOLEDAD_PRELOAD_SIZE)" \
	  --cidfile=$(CONTAINER_ID_FILE) \
	  --detach \
	  $(IMAGE_NAME) \
	  /usr/local/soledad/run-server.sh # --drop-to-shell

run-client-bootstrap:
	@if [ -z "$(CONTAINER_ID_FILE)" ]; then \
	  echo "Error: you have to pass a value to CONTAINER_ID_FILE."; \
	  exit 2; \
	fi
	container_id=`cat $(CONTAINER_ID_FILE)`; \
	server_ip=`./helper/get-container-ip.sh $${container_id}`; \
	docker run -t -i \
	  --memory="$(MEMORY)" \
	  --env="SOLEDAD_REMOTE=$(SOLEDAD_REMOTE)" \
	  --env="SOLEDAD_BRANCH=$(SOLEDAD_BRANCH)" \
	  --env="SOLEDAD_SERVER_URL=http://$${server_ip}:2424" \
	  $(IMAGE_NAME) \
	  /usr/local/soledad/run-client-bootstrap.sh

#################################################
# Run all tests inside a docker container       #
#################################################

run-tox:
	name=$$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 5 | head -n 1); \
	docker run -d --name $${name} leap/couchdb; \
	docker run -t -i \
	  --memory="$(MEMORY)" \
	  --env="SOLEDAD_REMOTE=$(SOLEDAD_REMOTE)" \
	  --env="SOLEDAD_BRANCH=$(SOLEDAD_BRANCH)" \
	  --env="COUCH_URL=http://$${name}:5984" \
	  --link $${name} \
	  $(IMAGE_NAME) \
	  /usr/local/soledad/run-tox.sh

############################################
# Performance tests and graphic generation #
############################################

run-perf:
	name=$$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 5 | head -n 1); \
	docker run -d --name $${name} leap/couchdb; \
	docker run -t -i \
	  --memory="$(MEMORY)" \
	  --env="SOLEDAD_REMOTE=$(SOLEDAD_REMOTE)" \
	  --env="SOLEDAD_BRANCH=$(SOLEDAD_BRANCH)" \
	  --env="SOLEDAD_PRELOAD_NUM=$(SOLEDAD_PRELOAD_NUM)" \
	  --env="COUCH_URL=http://$${name}:5984" \
	  --link $${name} \
	  $(IMAGE_NAME) \
	  /usr/local/soledad/run-perf.sh

run-client-perf:
	@if [ -z "$(CONTAINER_ID_FILE)" ]; then \
	  echo "Error: you have to pass a value to CONTAINER_ID_FILE."; \
	  exit 2; \
	fi
	container_id=`cat $(CONTAINER_ID_FILE)`; \
	server_ip=`./helper/get-container-ip.sh $${container_id}`; \
	docker run -t -i \
	  --memory="$(MEMORY)" \
	  --cpuset-cpus=1 \
	  --cidfile=$(CONTAINER_ID_FILE)-perf \
	  --env="SOLEDAD_REMOTE=$(SOLEDAD_REMOTE)" \
	  --env="SOLEDAD_BRANCH=$(SOLEDAD_BRANCH)" \
	  --env="SOLEDAD_PERF_REMOTE=https://0xacab.org/drebs/soledad-perf.git" \
	  --env="SOLEDAD_PERF_BRANCH=bug/ensure-events-server" \
	  --env="SOLEDAD_PRELOAD_NUM=$(SOLEDAD_PRELOAD_NUM)" \
	  --env="SOLEDAD_PRELOAD_SIZE=$(SOLEDAD_PRELOAD_SIZE)" \
	  --env="SOLEDAD_STATS=1" \
	  --env="SOLEDAD_SERVER_URL=http://$${server_ip}:2424" \
	  --env="SOLEDAD_LOG=1" \
	  $(IMAGE_NAME) \
	  /usr/local/soledad/run-client-perf.sh # --drop-to-shell

cp-perf-result:
	@if [ -z "$(CONTAINER_ID_FILE)" ]; then \
	  echo "Error: you have to pass a value to CONTAINER_ID_FILE."; \
	  exit 2; \
	fi
	perf_id=`cat $(CONTAINER_ID_FILE)-perf`; \
	docker cp $${perf_id}:/var/local/soledad-perf/out/sync-stats.png /tmp/; \
	docker cp $${perf_id}:/var/local/soledad-perf/out/series.log /tmp/

########################
# Other helper targets #
########################

run-shell: soledad-image
	docker run -t -i \
	  --memory="$(MEMORY)" \
	  $(IMAGE_NAME) \
	  /bin/bash

rm-all-containers:
	containers=`docker ps -a | cut -d" " -f 1 | tail -n +2 | xargs`; \
	if [ ! -z "$${containers}" ]; then docker rm -f $${containers}; fi
