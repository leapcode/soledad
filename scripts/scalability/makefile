# Test Controller Makefile
# ========================
#
# This makefile knows how to install server and client components of the Test
# Controller, as well as to trigger a run of the benchmarks.
#
# See the file README.rst for more information on how to use this makefile.


URI  ?= https://giraffe.cdev.bitmask.net:7001
SIZE ?= 10

PIDFILE = /tmp/test_controller.pid
LOGFILE = /tmp/test_controller.log
TACFILE = ./test_controller/server/server.tac


all: test


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
	(cd test_controller/client && make test URI=$(URI) SIZE=$(SIZE))
