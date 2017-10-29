# Test Controller for Server Scalability Tests
# ============================================
#
# This makefile knows how to install server and client components of the Test
# Controller, as well as to trigger a run of the benchmarks.
#
# Test Controller server
# ----------------------
#
# In the server, run the following to have an instance of the Test Controller
# server running:
#
#   make install-server
#   make start-server
#
# And, if you want to see the logs, use:
#
#   make log
#
# Alternativelly, use `make start-server-nodaemon` to avoid detaching from the
# terminal.
#
# Test Controller client
# ----------------------
#
# Make sure an instance of the Test Controller Server is reachable at $(URI),
# and run:
#
#   make install-client
#   make run-test


URI = https://giraffe.cdev.bitmask.net:7001

PIDFILE   = /tmp/test_controller.pid
LOGFILE   = /tmp/test_controller.log
TACFILE   = ./test_controller/server/server.tac


#----------------#
# Server targets #
#----------------#

install-server:
	pip install ".[server]"

start-server:
	twistd --pidfile=$(PIDFILE) --logfile=$(LOGFILE) --python=$(TACFILE)

start-server-nodaemon:
	twistd --nodaemon --python=$(TACFILE)

kill:
	[ -f $(PIDFILE) ] && kill -9 $$(cat $(PIDFILE))

log:
	tail -F $(LOGFILE)

restart: kill start


#----------------#
# Client targets #
#----------------#

install-client:
	pip install ".[client]"

test:
	(cd test_controller/client && make test URI=$(URI))
