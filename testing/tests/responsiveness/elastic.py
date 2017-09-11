import datetime
import elasticsearch

from pytest_benchmark.plugin import pytest_benchmark_generate_machine_info
from pytest_benchmark.utils import get_commit_info, get_tag, get_machine_id
from pytest_benchmark.storage.elasticsearch import BenchmarkJSONSerializer


def post(seconds_blocked, request,):
    body, doc_id = get_doc(seconds_blocked, request)
    url = request.config.getoption("elasticsearch_url")
    if url:
        es = elasticsearch.Elasticsearch(
            hosts=[url],
            serializer=BenchmarkJSONSerializer())
        es.index(
            index='responsiveness',
            doc_type='responsiveness',
            id=doc_id,
            body=body)
    else:
        print body


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
