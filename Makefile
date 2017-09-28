default:
.PHONY :  upload_packages

upload_packages:
	python setup.py sdist bdist_wheel --universal upload  --sign -i $(MAINTAINER) -r pypi
