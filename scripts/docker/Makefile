#/usr/bin/env

IMAGE_NAME = "leap/soledad:1.0"

all: image

image:
	docker build -t $(IMAGE_NAME) .

run-server: image
	rm -f $(CONTAINER_ID_FILE)
	docker run \
	  --env="SOLEDAD_REMOTE=https://0xacab.org/leap/soledad.git" \
	  --env="SOLEDAD_BRANCH=develop" \
	  --cidfile=$(CONTAINER_ID_FILE) \
	  --detach \
	  $(IMAGE_NAME) \
	  /usr/local/soledad/start-server.sh

# TODO: the following rule does not work for now, we have to add a
# `start-test.sh` file
run-test: image
	container_id=`cat $(CONTAINER_ID_FILE)`; \
	server_ip=`./helper/get-container-ip.sh $${container_id}`; \
	docker run \
	  --env="SOLEDAD_REMOTE=https://0xacab.org/leap/soledad.git" \
	  --env="SOLEDAD_BRANCH=develop" \
	  --env="SOLEDAD_SERVER_IP=$${server_ip}" \
	  $(IMAGE_NAME) \
	  /usr/local/soledad/start-test.sh
