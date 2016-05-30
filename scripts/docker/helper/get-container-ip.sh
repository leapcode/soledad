#!/bin/sh

# Print the IP of a container to stdout, given its id. Check the output for
# the `docker inspect` commmand for more details:
#
#   https://docs.docker.com/engine/reference/commandline/inspect/

if [ ${#} -ne 1 ]; then
  echo "Usage: ${0} container_id"
  exit 1
fi

container_id=${1}

/usr/bin/docker \
  inspect \
  --format='{{.NetworkSettings.IPAddress}}' \
  ${container_id}
