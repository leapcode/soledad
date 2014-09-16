#!/usr/bin/python


# Create a plot of the results of running the ./benchmark-storage.py script.


import argparse
from matplotlib import pyplot as plt

from sets import Set


def plot(filename, subtitle=''):

    # config the plot
    plt.xlabel('doc size (KB)')
    plt.ylabel('operation time (s)')
    title = 'soledad 1000 docs creation/retrieval times'
    if subtitle != '':
        title += '- %s' % subtitle
    plt.title(title)

    x = Set()
    ycreate = []
    yget = []

    ys = []
    #ys.append((ycreate, 'creation time', 'r', '-'))
    #ys.append((yget, 'retrieval time', 'b', '-'))

    # read data from file
    with open(filename, 'r') as f:
        f.readline()
        for i in xrange(6):
            size, y = f.readline().strip().split(' ')
            x.add(int(size))
            ycreate.append(float(y))

        f.readline()
        for i in xrange(6):
            size, y = f.readline().strip().split(' ')
            x.add(int(size))
            yget.append(float(y))

    # get doc size in KB
    x = list(x)
    x.sort()
    x = map(lambda val: val / 1024, x)

    # get normalized results per KB
    nycreate = []
    nyget = []
    for i in xrange(len(x)):
        nycreate.append(ycreate[i]/x[i])
        nyget.append(yget[i]/x[i])

    ys.append((nycreate, 'creation time per KB', 'r', '-.'))
    ys.append((nyget, 'retrieval time per KB', 'b', '-.'))

    for y in ys:
        kwargs = {
            'linewidth': 1.0,
            'marker': '.',
            'color': y[2],
            'linestyle': y[3],
        }
        # normalize by doc size
        plt.plot(
            x,
            y[0],
            label=y[1], **kwargs)

    #plt.axes().get_xaxis().set_ticks(x)
    #plt.axes().get_xaxis().set_ticklabels(x)

    # annotate max and min values
    plt.xlim(0, 1100)
    #plt.ylim(0, 350)
    plt.grid()
    plt.legend()
    plt.show()


if __name__ == '__main__':
    # parse command line
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'datafile',
        help='the data file to plot')
    parser.add_argument(
        '-s', dest='subtitle', required=False, default='',
        help='a subtitle for the plot')
    args = parser.parse_args()
    plot(args.datafile, args.subtitle)
