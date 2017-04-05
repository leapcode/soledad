#!/usr/bin/env python

import os
import tempfile

from pysqlcipher import dbapi2


def have_usleep():
    fname = tempfile.mktemp()
    db = dbapi2.connect(fname)
    cursor = db.cursor()
    cursor.execute('PRAGMA compile_options;')
    options = map(lambda t: t[0], cursor.fetchall())
    db.close()
    os.unlink(fname)
    return u'HAVE_USLEEP' in options


if __name__ == '__main__':
    if not have_usleep():
        raise Exception('pysqlcipher was not built with HAVE_USLEEP flag.')
    print "All ok, pysqlcipher was built with HAVE_USLEEP flag. :-)"
