from collections import namedtuple
ACCEPTED_FLAGS = ['PENDING', 'PROCESSING', 'PROCESSED', 'FAILED']
Flags = namedtuple('Flags', ' '.join(ACCEPTED_FLAGS))(*ACCEPTED_FLAGS)
