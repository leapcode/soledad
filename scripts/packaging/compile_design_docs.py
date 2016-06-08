#!/usr/bin/python


# This script builds files for the design documents represented in the
# ../common/src/soledad/common/ddocs directory structure (relative to the
# current location of the script) into a target directory.


import argparse
from os import listdir
from os.path import realpath, dirname, isdir, join, isfile, basename
import json

DDOCS_REL_PATH = ('..', 'common', 'src', 'leap', 'soledad', 'common', 'ddocs')


def build_ddocs():
    """
    Build design documents.

    For ease of development, couch backend design documents are stored as
    `.js` files in  subdirectories of
    `../common/src/leap/soledad/common/ddocs`. This function scans that
    directory for javascript files, and builds the design documents structure.

    This funciton uses the following conventions to generate design documents:

      - Design documents are represented by directories in the form
        `<prefix>/<ddoc>`, there prefix is the `src/leap/soledad/common/ddocs`
        directory.
      - Design document directories might contain `views`, `lists` and
        `updates` subdirectories.
      - Views subdirectories must contain a `map.js` file and may contain a
        `reduce.js` file.
      - List and updates subdirectories may contain any number of javascript
        files (i.e. ending in `.js`) whose names will be mapped to the
        corresponding list or update function name.
    """
    ddocs = {}

    # design docs are represented by subdirectories of `DDOCS_REL_PATH`
    cur_pwd = dirname(realpath(__file__))
    ddocs_path = join(cur_pwd, *DDOCS_REL_PATH)
    for ddoc in [f for f in listdir(ddocs_path)
                 if isdir(join(ddocs_path, f))]:

        ddocs[ddoc] = {'_id': '_design/%s' % ddoc}

        for t in ['views', 'lists', 'updates']:
            tdir = join(ddocs_path, ddoc, t)
            if isdir(tdir):

                ddocs[ddoc][t] = {}

                if t == 'views':  # handle views (with map/reduce functions)
                    for view in [f for f in listdir(tdir)
                                 if isdir(join(tdir, f))]:
                        # look for map.js and reduce.js
                        mapfile = join(tdir, view, 'map.js')
                        reducefile = join(tdir, view, 'reduce.js')
                        mapfun = None
                        reducefun = None
                        try:
                            with open(mapfile) as f:
                                mapfun = f.read()
                        except IOError:
                            pass
                        try:
                            with open(reducefile) as f:
                                reducefun = f.read()
                        except IOError:
                            pass
                        ddocs[ddoc]['views'][view] = {}

                        if mapfun is not None:
                            ddocs[ddoc]['views'][view]['map'] = mapfun
                        if reducefun is not None:
                            ddocs[ddoc]['views'][view]['reduce'] = reducefun

                else:  # handle lists, updates, etc
                    for fun in [f for f in listdir(tdir)
                                if isfile(join(tdir, f))]:
                        funfile = join(tdir, fun)
                        funname = basename(funfile).replace('.js', '')
                        try:
                            with open(funfile) as f:
                                ddocs[ddoc][t][funname] = f.read()
                        except IOError:
                            pass
    return ddocs


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'target', type=str,
        help='the target dir where to store design documents')
    args = parser.parse_args()

    # check if given target is a directory
    if not isdir(args.target):
        print 'Error: %s is not a directory.' % args.target
        exit(1)

    # write desifgn docs files
    ddocs = build_ddocs()
    for ddoc in ddocs:
        ddoc_filename = "%s.json" % ddoc
        with open(join(args.target, ddoc_filename), 'w') as f:
            f.write("%s" % json.dumps(ddocs[ddoc], indent=3))
        print "Wrote _design/%s content in %s" \
              % (ddoc, join(args.target, ddoc_filename,))
