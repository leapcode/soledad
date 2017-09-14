VIRTUALENV_NAME = plot
VIRTUALENV_ROOT = ~/.virtualenvs/$(VIRTUALENV_NAME)

all: graph

env:
	if [ ! -d $(VIRTUALENV_ROOT) ]; then \
	  mkdir -p $$(dirname $(VIRTUALENV_ROOT)); \
	  virtualenv $(VIRTUALENV_ROOT); \
	fi

deps: env
	$(VIRTUALENV_ROOT)/bin/pip install -r requirements.pip

graph: deps
	$(VIRTUALENV_ROOT)/bin/python ./gen-graph.py
