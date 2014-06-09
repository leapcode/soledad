#!/usr/bin/python


import argparse
from matplotlib import pyplot as plt
from movingaverage import movingaverage
from scipy.interpolate import interp1d
from numpy import linspace


def smooth(l):
    return movingaverage(l, 3, data_is_list=True, avoid_fp_drift=False)


def plot(filename, subtitle=''):

    # config the plot
    plt.xlabel('time (s)')
    plt.ylabel('usage (%)')
    title = 'soledad sync'
    if subtitle != '':
        title += '- %s' % subtitle
    plt.title(title)

    x = []
    ycpu = []
    ymem = []
    ypcpu = []
    ypmem = []

    ys = [
        (ycpu, 'total cpu', 'r'),
        (ymem, 'total mem', 'b'),
        (ypcpu, 'proc cpu', 'm'),
        (ypmem, 'proc mem', 'g'),
    ]

    # read data from file
    with open(filename, 'r') as f:
        line = f.readline()
        while True:
            line = f.readline()
            if line.startswith('#'):
                continue
            if line == '' or line is None:
                break
            time, cpu, mem, pcpu, pmem = tuple(line.strip().split(' '))
            x.append(float(time))
            ycpu.append(float(cpu))
            ymem.append(float(mem))
            ypcpu.append(float(pcpu))
            ypmem.append(float(pmem))

    smoothx = [n for n in smooth(x)]
    #xnew = linspace(0.01, 19, 100)

    for y in ys:
        kwargs = {
            'linewidth': 1.0,
            'linestyle': '-',
        #    'marker': '.',
            'color': y[2],
        }
        #f = interp1d(x, y[0], kind='cubic')
        plt.plot(
            smoothx,
            [n for n in smooth(y[0])],
            #xnew,
            #f(xnew),
            label=y[1], **kwargs)

    #plt.axes().get_xaxis().set_ticks(x)
    #plt.axes().get_xaxis().set_ticklabels(x)

    # annotate max and min values
    plt.xlim(0, 20)
    plt.ylim(0, 100)
    plt.grid()
    plt.legend()
    plt.show()


if __name__ == '__main__':
    # parse command line
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-d', dest='datafile', required=False, default='/tmp/profile.log',
        help='the data file to plot')
    parser.add_argument(
        '-s', dest='subtitle', required=False, default='',
        help='a subtitle for the plot')
    args = parser.parse_args()
    plot(args.datafile, args.subtitle)
