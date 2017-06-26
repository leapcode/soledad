import csv
from matplotlib import pyplot as plt

FILE = "bench.csv"

# config the plot
plt.xlabel('number of inserts')
plt.ylabel('time (seconds)')
plt.title('SQLCipher parallelization')

kwargs = {
    'linewidth': 1.0,
    'linestyle': '-',
}

series = (('sync', 'r'),
          ('async', 'g'))

data = {'mark': [],
        'sync': [],
        'async': []}

with open(FILE, 'rb') as csvfile:
    series_reader = csv.reader(csvfile, delimiter=',')
    for m, s, a in series_reader:
        data['mark'].append(int(m))
        data['sync'].append(float(s))
        data['async'].append(float(a))

xmax = max(data['mark'])
xmin = min(data['mark'])
ymax = max(data['sync'] + data['async'])
ymin = min(data['sync'] + data['async'])

for run in series:
    name = run[0]
    color = run[1]
    plt.plot(data['mark'], data[name], label=name, color=color, **kwargs)

plt.axes().annotate("", xy=(xmax, ymax))
plt.axes().annotate("", xy=(xmin, ymin))

plt.grid()
plt.legend()
plt.show()
