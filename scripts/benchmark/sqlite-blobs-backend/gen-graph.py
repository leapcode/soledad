#!/usr/bin/env python

# Plot bars comparing different implementations of mail pipeline.
#
# This script can be improved to account for arbitrary number of data sets, but
# it is not doing it right now.

import json
import matplotlib.pyplot as plt
import numpy as np
import re

# make a prettier graph
from mpltools import style
style.use('ggplot')

OUTPUT_FILENAME = 'blobs-sqlite-backend.png'

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
#   data[get/put][amount_size] = <stats>

def get_data():
    data = {}
    for fname in ['get', 'put']:
        data[fname] = {}
        with open('data/%s.json' % fname) as f:
            d = json.loads(f.read())
            benchmarks = d['benchmarks']
            for item in benchmarks:
                name = re.sub('^[^1]+', '', item['name'])
                data[fname][name] = item['stats']
    return data


def plot_data(data):

    N = 4

    get_means = tuple([data['get'][graph]['mean'] for graph in graphs])
    put_means = tuple([data['put'][graph]['mean'] for graph in graphs])

    ind = np.arange(N)  # the x locations for the groups
    width = 0.40        # the width of the bars

    fig, ax = plt.subplots()
    rects1 = ax.bar(ind, get_means, width)
    rects2 = ax.bar(ind + width, put_means, width)

    # add some text for labels, title and axes ticks
    ax.set_ylabel('Time for operation (s)')
    ax.set_xlabel('Amount and size of blobs')
    ax.set_title('Blobs storage and retrieval time')
    ax.set_xticks(ind + (0.5 * width))
    ax.set_xticklabels(
        tuple(map(lambda name: name.replace('_', ' x '), graphs)))

    ax.legend(
        (rects1[0], rects2[0]),
        ('retrieval time', 'storage time'))
    # ax.grid()

    plt.savefig(OUTPUT_FILENAME)
    # plt.show()


if __name__ == '__main__':
    data = get_data()
    plot_data(data)
