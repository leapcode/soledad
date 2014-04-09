#!/usr/bin/python


from matplotlib import pyplot as plt
from movingaverage import movingaverage


def smooth(l):
    return movingaverage(l, 10, data_is_list=True, avoid_fp_drift=False)


files = [
    ('sqlite', 'b'),
    ('sqlcipher', 'r'),
    ('u1dblite', 'g'),
    ('u1dbcipher', 'm'),
]


# config the plot
plt.xlabel('time (s)')
plt.ylabel('cpu usage (%)')
plt.title('u1db backends CPU usage')


for fi in files:

    backend = fi[0]
    color = fi[1]
    filename = '%s.txt' % backend 

    x = []
    y = []

    xmax = None
    xmin = None
    ymax = None
    ymin = None

    # read data from file
    with open(filename, 'r') as f:
        line = f.readline()
        while line is not None:
            time, cpu = tuple(line.strip().split(' '))
            cpu = float(cpu)
            x.append(float(time))
            y.append(cpu)
            if ymax == None or cpu > ymax:
                ymax = cpu
                xmax = time
            if ymin == None or cpu < ymin:
                ymin = cpu
                xmin = time
            line = f.readline()
            if line == '':
                break

    kwargs = {
        'linewidth': 1.0,
        'linestyle': '-',
    #    'marker': '.',
        'color': color,
    }
    plt.plot(
        [n for n in smooth(x)],
        [n for n in smooth(y)],
        label=backend, **kwargs)

    #plt.axes().get_xaxis().set_ticks(x)
    #plt.axes().get_xaxis().set_ticklabels(x)

    # annotate max and min values
    #plt.axes().annotate("%.2f GB" % ymax, xy=(xmax, ymax))
    #plt.axes().annotate("%.2f GB" % ymin, xy=(xmin, ymin))


plt.ylim(0, 100)
plt.grid()
plt.legend()
plt.show()

