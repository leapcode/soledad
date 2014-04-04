#!/usr/bin/python


from matplotlib import pyplot as plt


files = [
    ('local', 'couchdb-json', 'b'),
    ('local', 'bigcouch-json', 'r'),
    ('local', 'couchdb-multipart', 'g'),
    ('local', 'bigcouch-multipart', 'm'),
]


# config the plot
plt.xlabel('time')
plt.ylabel('memory usage')
plt.title('bigcouch versus couch memory usage')


for fi in files:

    machine = fi[0]
    database = fi[1]
    color = fi[2]
    filename = '%s-%s.txt' % (machine, database)

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
            time, mem = tuple(line.strip().split(' '))
            mem = float(mem) / (10**9)
            x.append(float(time))
            y.append(mem)
            if ymax == None or mem > ymax:
                ymax = mem
                xmax = time
            if ymin == None or mem < ymin:
                ymin = mem
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
    plt.plot(x, y, label=database, **kwargs)

    #plt.axes().get_xaxis().set_ticks(x)
    #plt.axes().get_xaxis().set_ticklabels(x)

    # annotate max and min values
    #plt.axes().annotate("%.2f GB" % ymax, xy=(xmax, ymax))
    #plt.axes().annotate("%.2f GB" % ymin, xy=(xmin, ymin))


plt.grid()
plt.legend()
plt.show()

