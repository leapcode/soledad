default:
.PHONY :  upload_packages

upload_packages:
	python setup.py sdist bdist_wheel --universal upload  --sign -i $(MAINTAINER) -r pypi

docs:
	(cd docs && make html)

docs-using-virtualenv:
	./scripts/docs/build-soledad-doc.sh
