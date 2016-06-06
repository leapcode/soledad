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
#   make run-client-test CONTAINER_ID_FILE=/tmp/container-id.txt


IMAGE_NAME        ?= "leap/soledad:1.0"
SOLEDAD_REMOTE    ?= "https://0xacab.org/leap/soledad.git"
SOLEDAD_BRANCH    ?= "develop"


all: image

image:
	docker build -t $(IMAGE_NAME) .

run-server:
	@if [ -z "$(CONTAINER_ID_FILE)" ]; then \
	  echo "Error: you have to pass a value to CONTAINER_ID_FILE."; \
	  exit 2; \
	fi
	docker run \
	  --env="SOLEDAD_REMOTE=$(SOLEDAD_REMOTE)" \
	  --env="SOLEDAD_BRANCH=$(SOLEDAD_BRANCH)" \
	  --cidfile=$(CONTAINER_ID_FILE) \
	  --detach \
	  $(IMAGE_NAME) \
	  /usr/local/soledad/start-server.sh

run-client-test:
	@if [ -z "$(CONTAINER_ID_FILE)" ]; then \
	  echo "Error: you have to pass a value to CONTAINER_ID_FILE."; \
	  exit 2; \
	fi
	container_id=`cat $(CONTAINER_ID_FILE)`; \
	server_ip=`./helper/get-container-ip.sh $${container_id}`; \
	docker run -t -i \
	  --env="SOLEDAD_REMOTE=$(SOLEDAD_REMOTE)" \
	  --env="SOLEDAD_BRANCH=$(SOLEDAD_BRANCH)" \
	  --env="SOLEDAD_SERVER_URL=http://$${server_ip}:2424" \
	  $(IMAGE_NAME) \
	  /usr/local/soledad/start-client-test.sh

run-trial-test:
	docker run -t -i \
	  --env="SOLEDAD_REMOTE=$(SOLEDAD_REMOTE)" \
	  --env="SOLEDAD_BRANCH=$(SOLEDAD_BRANCH)" \
	  $(IMAGE_NAME) \
	  /usr/local/soledad/start-trial-test.sh

run-shell: image
	docker run -t -i $(IMAGE_NAME) /bin/bash

rm-all-containers:
	docker ps -a | cut -d" " -f 1 | tail -n +2 | xargs docker rm -f
