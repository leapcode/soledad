#!/usr/bin/env python

import base64
import errno
import os
import random


def payload(size):
    random.seed(1337)  # same seed to avoid different bench results
    payload_bytes = bytearray(random.getrandbits(8) for _ in xrange(size))
    # encode as base64 to avoid ascii encode/decode errors
    return base64.b64encode(payload_bytes)[:size]  # remove b64 overhead


def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc:  # Python >2.5
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise
