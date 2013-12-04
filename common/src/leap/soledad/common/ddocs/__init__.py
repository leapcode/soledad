# -*- coding: utf-8 -*-
# __init__.py
# Copyright (C) 2013 LEAP
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.


"""
CouchDB U1DB backend design documents helper.
"""


from os import listdir
from os.path import realpath, dirname, isdir, join, isfile, basename
import json
import logging


from couchdb import Document as CouchDocument


logger = logging.getLogger(__name__)


# where to search for design docs definitions
prefix = dirname(realpath(__file__))


def ensure_ddocs_on_remote_db(db, prefix=prefix):
    """
    Ensure that the design documents in C{db} contain.

    :param db: The database in which to create/update the design docs.
    :type db: couchdb.client.Server
    :param prefix: Where to look for design documents definitions.
    :type prefix: str
    """
    ddocs = build_ddocs(prefix)
    for ddoc_name, ddoc_content in ddocs.iteritems():
        ddoc_id = "_design/%s" % ddoc_name
        ddoc = CouchDocument({'_id': ddoc_id})
        ddoc.update(ddoc_content)
        # ensure revision if ddoc is already in db
        doc = db.get(ddoc_id)
        if doc is not None:
            ddoc['_rev'] = doc.rev
        db.save(ddoc)


def create_local_ddocs(prefix=prefix):
    """
    Create local design docs based on content from subdirectories in
    C{prefix}.

    :param create_local: Whether to create local .json files.
    :type create_local: bool
    """
    ddocs = build_ddocs(prefix)
    for ddoc_name, ddoc_content in ddocs.iteritems():
        with open(join(prefix, '%s.json' % ddoc_name), 'w') as f:
            f.write(json.dumps(ddoc_content, indent=4))


def build_ddocs(prefix=prefix):
    """
    Build design documents based on content from subdirectories in
    C{prefix}.

    :param prefix: Where to look for design documents definitions.
    :type prefix: str

    :return: A dictionary containing the design docs definitions.
    :rtype: dict
    """
    ddocs = {}
    # design docs are represented by subdirectories in current directory
    for ddoc in [f for f in listdir(prefix) if isdir(join(prefix, f))]:
        logger.debug("Building %s.json ..." % ddoc)

        ddocs[ddoc] = {}

        for t in ['views', 'lists', 'updates']:
            tdir = join(prefix, ddoc, t)
            if not isdir(tdir):
                logger.debug("  - no %s" % t)
            else:

                ddocs[ddoc][t] = {}

                if t == 'views':  # handle views (with map/reduce functions)
                    for view in [f for f in listdir(tdir) \
                            if isdir(join(tdir, f))]:
                        logger.debug("  - view: %s" % view)
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
                    for fun in [f for f in listdir(tdir) \
                            if isfile(join(tdir, f))]:
                        logger.debug("  - %s: %s" % (t, fun))
                        funfile = join(tdir, fun)
                        funname = basename(funfile).replace('.js', '')
                        try:
                            with open(funfile) as f:
                                ddocs[ddoc][t][funname] = f.read()
                        except IOError:
                            pass
    return ddocs
