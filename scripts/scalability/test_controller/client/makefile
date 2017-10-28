bench: upload download

upload:
	curl -X POST "http://127.0.0.1:7001/blobs?action=delete"
	fl-run-bench -f test_Blobs.py Blobs.test_upload
	fl-build-report --html results/blobs-bench.xml

download:
	curl -X POST "http://127.0.0.1:7001/blobs?action=create&size=10&amount=5000"
	fl-run-bench -f test_Blobs.py Blobs.test_download
	fl-build-report --html results/blobs-bench.xml

test_upload:
	curl -X POST "http://127.0.0.1:7001/blobs?action=delete"
	fl-run-bench -c 1 --duration 10 -f test_Blobs.py Blobs.test_upload

test_download:
	curl -X POST "http://127.0.0.1:7001/blobs?action=create&size=10"
	fl-run-bench -c 1 --duration 10 -f test_Blobs.py Blobs.test_download
