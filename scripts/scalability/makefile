PIDFILE   = /tmp/test_controller.pid
LOGFILE   = /tmp/test_controller.log
TACFILE   = ./test_controller/server/server.tac
HTTP_PORT = 7001
RESOURCE  = cpu

start:
	twistd --pidfile=$(PIDFILE) --logfile=$(LOGFILE) --python=$(TACFILE)

nodaemon:
	twistd --nodaemon --python=$(TACFILE)

kill:
	[ -f $(PIDFILE) ] && kill -9 $$(cat $(PIDFILE))

log:
	tail -F $(LOGFILE)

restart: kill start

post:
	curl -X POST http://127.0.0.1:$(HTTP_PORT)/$(RESOURCE)?pid=$(PID)

get:
	curl -X GET http://127.0.0.1:$(HTTP_PORT)/$(RESOURCE)

setup:
	curl -X POST http://127.0.0.1:$(HTTP_PORT)/setup
