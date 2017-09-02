#!/usr/bin/env python

# Plot bars comparing different implementations of mail pipeline.
#
# This script can be improved to account for arbitrary number of data sets, but
# it is not doing it right now.

import json
import numpy as np
import matplotlib.pyplot as plt

# make a prettier graph
from mpltools import style
style.use('ggplot')

OUTPUT_FILENAME = 'legacy-vs-blobs.png'

# each value below will generate one bar for each for each (amount, size) pair.
# The script expects to find files in ./data/SET/ for each set of
# implementations.
#
# The baseline values will be the legacy results in ./data/no-cache/.

graphs = [
    '1_10000k',
    '10_1000k',
    '100_100k',
    '1000_10k',
]


# the JSON structure returned by the following function is ugly, but the
# original JSONs are even uglier, so this is here just to make the life of the
# script easier.
#
# We want to have something like:
#
#   data[variation][graph][implementation] = <stats>
#
# Where:
#
#   - variation is one data set under ./data (i.e. no-cache, cache, persistent,
#     etc).
#   - graph is one of the values in graphs variable above.
#   - implementation is either legacy or blobs (we just need legacy for the
#     no-cache variation, as that is the one we are using as baseline.

def get_data():
    folders = ['cache', 'no-cache', 'persistent']
    data = {}
    for folder in folders:
        data[folder] = {}
        for graph in graphs:
            with open('data/%s/%s.json' % (folder, graph)) as f:
                d = json.loads(f.read())
                benchmarks = d['benchmarks']
            data[folder][graph] = {}
            for t in ['blobs', 'legacy']:
                result = filter(lambda b: t in b['name'], benchmarks)
                if result:
                    result = result.pop()
                    data[folder][graph][t] = result['stats']
    return data


def plot_data(data):

    N = 4

    # this is our baseline (i.e. legacy / legacy)
    absolutes = (1, 1, 1, 1)

    ind = np.arange(N)  # the x locations for the groups
    width = 0.20        # the width of the bars

    fig, ax = plt.subplots()
    rects1 = ax.bar(ind, absolutes, width)

    # for each graph, calculate the ratios
    ratios = {'no-cache': [], 'cache': [], 'persistent': []}
    for graph in graphs:
        legacy = data['no-cache'][graph]['legacy']['mean']

        # calculate ratios for no-cache / legacy
        ratio = data['no-cache'][graph]['blobs']['mean'] / legacy
        ratios['no-cache'].append(ratio)

        # calculate ratios for cache / legacy
        ratio = data['cache'][graph]['blobs']['mean'] / legacy
        ratios['cache'].append(ratio)

        # calculate ratios for persistent / legacy
        ratio = data['persistent'][graph]['blobs']['mean'] / legacy
        ratios['persistent'].append(ratio)

    # create the boxes with the ratios
    nocache = tuple(ratios['no-cache'])
    rects2 = ax.bar(ind + width, nocache, width)

    cache = tuple(ratios['cache'])
    rects3 = ax.bar(ind + (2 * width), cache, width)

    persistent = tuple(ratios['persistent'])
    rects4 = ax.bar(ind + (3 * width), persistent, width)

    # add some text for labels, title and axes ticks
    ax.set_ylabel('Normalized execution time')
    ax.set_title('Legacy vs Blobs mail pipeline')
    ax.set_xticks(ind + (1.5 * width))
    ax.set_xticklabels(tuple(map(lambda name: name.replace('_', ' '), graphs)))

    ax.legend(
        (rects1[0], rects2[0], rects3[0], rects4[0]),
        ('legacy', 'blobs', 'blobs + session cache',
         'blobs + session cache + persistent http'))
    # ax.grid()

    plt.savefig(OUTPUT_FILENAME)
    # plt.show()


if __name__ == '__main__':
    data = get_data()
    plot_data(data)
