#!/usr/bin/env python

# Given a JSON file output by pytest-benchmark, this script compares the
# results of a test session with the results stored in elasticsearch.
#
#   - iterate through test results in pytest-benchmark JSON file.
#
#   - for each one, get mean and stddev of the mean of last 20 results from
#     master branch.
#
#   - compare the result in the file with the results in elastic.

import argparse
import copy
import json
import requests
import sys


URL = "https://moose.leap.se:9200/benchmark/_search"
BLOCK_SIZE = 20
MULTIPLIER = 1.5


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'file',
        help='The file with JSON results of pytest-benchmark')
    return parser.parse_args()


def parse_file(file):
    data = None
    tests = []
    with open(file) as f:
        data = json.loads(f.read())
    for test in data['benchmarks']:
        name = test['name']
        mean = test['stats']['mean']
        extra = test['extra_info']
        tests.append((name, mean, extra))
    return tests


base_query = {
    "query": {
        "bool": {
            "must": [
                {"term": {"machine_info.host": "weasel"}},
                {"term": {"commit_info.branch": "master"}},
                {"term": {"commit_info.project": "soledad"}},
                {"exists": {"field": "extra_info"}},
                {"exists": {"field": "extra_info.cpu_percent"}}
            ],
            "must_not": [
            ],
        },
    },
    "aggs": {
        "commit_id_time": {
            "terms": {
                "field": "commit_info.id",
                "size": BLOCK_SIZE,
                "order": {"commit_info_time": "desc"},
            },
            "aggs": {
                "commit_info_time": {"max": {"field": "commit_info.time"}},
            }
        }
    },
}


def get_time_cpu_stats(test):
    query = copy.deepcopy(base_query)
    query['query']['bool']['must'].append({
        'term': {'name': test}})
    query['query']['bool']['must_not'].append(
        {'exists': {'field': "extra_info.memory_percent"}})
    query['aggs']['commit_id_time']['aggs']['time'] = \
        {"stats": {"field": "stats.mean"}}
    query['aggs']['commit_id_time']['aggs']['cpu'] = \
        {"stats": {"field": "extra_info.cpu_percent"}}
    response = requests.get("%s?size=0" % URL, data=json.dumps(query))
    data = response.json()
    time = []
    cpu = []
    buckets = data['aggregations']['commit_id_time']['buckets']
    for bucket in buckets:
        time.append(bucket['time']['avg'])
        cpu.append(bucket['cpu']['avg'])
    return time, cpu


def get_mem_stats(test):
    query = copy.deepcopy(base_query)
    query['query']['bool']['must'].append({
        'term': {'name': test}})
    query['query']['bool']['must'].append(
        {'exists': {'field': "extra_info.memory_percent"}})
    query['aggs']['commit_id_time']['aggs']['mem'] = \
        {"stats": {"field": "extra_info.memory_percent.stats.max"}}
    response = requests.get("%s?size=0" % URL, data=json.dumps(query))
    data = response.json()
    mem = []
    buckets = data['aggregations']['commit_id_time']['buckets']
    for bucket in buckets:
        mem.append(bucket['mem']['avg'])
    return mem


def _mean(l):
    return float(sum(l)) / len(l)


def _std(l):
    if len(l) <= 1:
        return 0
    mean = _mean(l)
    squares = [(x - mean) ** 2 for x in l]
    return (sum(squares) / (len(l) - 1)) ** 0.5


def detect_bad_outlier(test, mean, extra):
    bad = False
    if 'memory_percent' in extra:
        mem = get_mem_stats(test)
        value = extra['memory_percent']['stats']['max']
        bad |= _detect_outlier('mem', value, mem) > 0
    else:
        time, cpu = get_time_cpu_stats(test)

        value = mean
        bad |= _detect_outlier('time', value, time) > 0

        value = extra['cpu_percent']
        bad |= _detect_outlier('cpu', value, cpu) > 0
    return bad


def _detect_outlier(name, value, list):
    mean = _mean(list)
    std = _std(list)
    result = 0
    print "%s: %f ? %f +- %f * %f" \
          % (name, value, mean, MULTIPLIER, std)
    if value < mean - MULTIPLIER * std:
        print "%s: %f < %f - %f * %f" \
              % (name, value, mean, MULTIPLIER, std)
        result = -1
    elif value > mean + MULTIPLIER * std:
        print "%s: %f > %f - %f * %f" \
              % (name, value, mean, MULTIPLIER, std)
        result = 1
    return result


if __name__ == '__main__':
    args = parse_args()
    tests = parse_file(args.file)
    failed = False
    for test, mean, extra in tests:
        failed |= detect_bad_outlier(test, mean, extra)
    if failed:
        sys.exit(1)
