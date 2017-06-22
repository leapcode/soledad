default:
.PHONY :  upload_packages

upload_packages:
	cd common && python setup.py sdist bdist_wheel --universal upload  --sign -i $(MAINTAINER) -r pypi
	cd client && python setup.py sdist bdist_wheel --universal upload  --sign -i $(MAINTAINER) -r pypi
	cd server && python setup.py sdist bdist_wheel --universal upload  --sign -i $(MAINTAINER) -r pypi
