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

run-client-test: image
	container_id=`cat $(CONTAINER_ID_FILE)`; \
	server_ip=`./helper/get-container-ip.sh $${container_id}`; \
	docker run -t -i \
	  --env="SOLEDAD_REMOTE=https://0xacab.org/leap/soledad.git" \
	  --env="SOLEDAD_BRANCH=develop" \
	  --env="SOLEDAD_SERVER_URL=http://$${server_ip}:2424" \
	  $(IMAGE_NAME) \
	  /usr/local/soledad/start-client-test.sh

rm-all-containers:
	docker ps -a | cut -d" " -f 1 | tail -n +2 | xargs docker rm -f
