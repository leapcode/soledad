# -*- coding: utf-8 -*-
# errors.py
# Copyright (C) 2015 LEAP
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
from leap.soledad.common.errors import SoledadError, BackendNotReadyError
from leap.soledad.common.errors import register_exception

"""
Specific errors that can be raised by CouchDatabase.
"""


@register_exception
class MissingDesignDocError(BackendNotReadyError):

    """
    Raised when trying to access a missing couch design document.
    """

    wire_description = "missing design document"
    status = 500


@register_exception
class MissingDesignDocNamedViewError(SoledadError):

    """
    Raised when trying to access a missing named view on a couch design
    document.
    """

    wire_description = "missing design document named function"
    status = 500


@register_exception
class MissingDesignDocListFunctionError(SoledadError):

    """
    Raised when trying to access a missing list function on a couch design
    document.
    """

    wire_description = "missing design document list function"
    status = 500


@register_exception
class MissingDesignDocDeletedError(SoledadError):

    """
    Raised when trying to access a deleted couch design document.
    """

    wire_description = "design document was deleted"
    status = 500


@register_exception
class DesignDocUnknownError(SoledadError):

    """
    Raised when trying to access a couch design document and getting an
    unknown error.
    """

    wire_description = "missing design document unknown error"
    status = 500


def raise_missing_design_doc_error(exc, ddoc_path):
    """
    Raise an appropriate exception when catching a ResourceNotFound when
    accessing a design document.

    :param exc: The exception cought.
    :type exc: ResourceNotFound
    :param ddoc_path: A list representing the requested path.
    :type ddoc_path: list

    :raise MissingDesignDocError: Raised when tried to access a missing design
                                  document.
    :raise MissingDesignDocListFunctionError: Raised when trying to access a
                                              missing list function on a
                                              design document.
    :raise MissingDesignDocNamedViewError: Raised when trying to access a
                                           missing named view on a design
                                           document.
    :raise MissingDesignDocDeletedError: Raised when trying to access a
                                         deleted design document.
    :raise MissingDesignDocUnknownError: Raised when failed to access a design
                                         document for an yet unknown reason.
    """
    path = "".join(ddoc_path)
    if exc.message[1] == 'missing':
        raise MissingDesignDocError(path)
    elif exc.message[1] == 'missing function' or \
            exc.message[1].startswith('missing lists function'):
        raise MissingDesignDocListFunctionError(path)
    elif exc.message[1] == 'missing_named_view':
        raise MissingDesignDocNamedViewError(path)
    elif exc.message[1] == 'deleted':
        raise MissingDesignDocDeletedError(path)
    # other errors are unknown for now
    raise DesignDocUnknownError("%s: %s" % (path, str(exc.message)))


def raise_server_error(exc, ddoc_path):
    """
    Raise an appropriate exception when catching a ServerError when
    accessing a design document.

    :param exc: The exception cought.
    :type exc: ResourceNotFound
    :param ddoc_path: A list representing the requested path.
    :type ddoc_path: list

    :raise MissingDesignDocListFunctionError: Raised when trying to access a
                                              missing list function on a
                                              design document.
    :raise MissingDesignDocUnknownError: Raised when failed to access a design
                                         document for an yet unknown reason.
    """
    path = "".join(ddoc_path)
    msg = exc.message[1][0]
    if msg == 'unnamed_error':
        raise MissingDesignDocListFunctionError(path)
    elif msg == 'TypeError':
        if 'point is undefined' in exc.message[1][1]:
            raise MissingDesignDocListFunctionError
    # other errors are unknown for now
    raise DesignDocUnknownError("%s: %s" % (path, str(exc.message)))
