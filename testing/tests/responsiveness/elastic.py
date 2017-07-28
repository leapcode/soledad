import datetime
import elasticsearch

from pytest_benchmark.plugin import pytest_benchmark_generate_machine_info
from pytest_benchmark.utils import get_commit_info, get_tag, get_machine_id
from pytest_benchmark.storage.elasticsearch import BenchmarkJSONSerializer


ELASTICSEARCH_URL = 'http://elastic:changeme@127.0.0.1:9200/'


def post(seconds_blocked, request):
    es = elasticsearch.Elasticsearch(
        hosts=[ELASTICSEARCH_URL],
        serializer=BenchmarkJSONSerializer())
    body, doc_id = get_doc(seconds_blocked, request)
    es.index(
        index='responsiveness',
        doc_type='responsiveness',
        id=doc_id,
        body=body)


def get_doc(seconds_blocked, request):
    fullname = request.node._nodeid
    name = request.node.name
    group = None
    marker = request.node.get_marker("responsivness")
    if marker:
        group = marker.kwargs.get("group")

    doc = {
        "datetime": datetime.datetime.utcnow().isoformat(),
        "commit_info": get_commit_info(),
        "fullname": fullname,
        "name": name,
        "group": group,
        "machine_info": pytest_benchmark_generate_machine_info(),
    }

    # generate a doc id like the one used by pytest-benchmark
    machine_id = get_machine_id()
    tag = get_tag()
    doc_id = machine_id + "_" + tag + "_" + fullname

    return doc, doc_id
