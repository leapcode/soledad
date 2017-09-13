VIRTUALENV_NAME = plot
VIRTUALENV_ROOT = ~/.virtualenvs/$(VIRTUALENV_NAME)

all: graph

env:
	if [ ! -d $(VIRTUALENV_ROOT) ]; then \
	  mkdir -p $$(dirname $(VIRTUALENV_ROOT)); \
	  virtualenv $(VIRTUALENV_ROOT); \
	  $(VIRTUALENV_ROOT)/bin/pip install requirements.pip; \
	fi

graph: env
	$(VIRTUALENV_ROOT)/bin/python ./legacy-vs-blobs.py
