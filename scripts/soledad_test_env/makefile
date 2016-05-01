CLI := python ./soledad_test_env.py

setup-env:
	$(CLI) couch start
	$(CLI) shared-db create
	$(CLI) token-db create
	$(CLI) token-db insert-token
	$(CLI) user-db create
	$(CLI) soledad-server start

destroy-env:
	$(CLI) soledad-server stop
	$(CLI) user-db delete
	$(CLI) token-db delete
	$(CLI) shared-db delete
	$(CLI) couch stop

test:
	$(CLI) soledad-client test
