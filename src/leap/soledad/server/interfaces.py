# -*- coding: utf-8 -*-
# interfaces.py
# Copyright (C) 2017 LEAP
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


from zope.interface import Interface


class IBlobsBackend(Interface):

    """
    An interface for a backend that can store blobs.

    Classes that implement this interface are supposed to be used by
    ``BlobsResource``, which is a ``twisted.web.resource.Resource`` that serves
    the Blobs API. Because of that, their methods receive instances of
    ``twisted.web.server.Request`` and should use them to serve the Blobs API.
    """

    def read_blob(user, blob_id, request, namespace=''):
        """
        Read a blob from the backend storage and write it as a response to a
        request.

        :param user: The id of the user who owns the blob.
        :type user: str
        :param blob_id: The id of the blob.
        :type blob_id: str
        :param request: A representation of all of the information about the
            request that is being made.
        :type request: twisted.web.server.Request
        :param namespace: An optional namespace for the blob.
        :type namespace: str

        :return: Either ``server.NOT_DONE_YET`` to indicate an asynchronous
            operation or a ``bytes`` instance to write as the response to the
            request. If ``NOT_DONE_YET`` is returned, at some point later (for
            example, in a Deferred callback) call ``request.write(b"data")`` to
            write data to the request, and ``request.finish()`` to send the
            data to the browser.
        """

    def write_blob(user, blob_id, request, namespace=''):
        """
        Write a blob to the backend storage after reading it from a request.

        :param user: The id of the user who owns the blob.
        :type user: str
        :param blob_id: The id of the blob.
        :type blob_id: str
        :param request: A representation of all of the information about the
            request that is being made.
        :type request: twisted.web.server.Request
        :param namespace: An optional namespace for the blob.
        :type namespace: str

        :return: A deferred that fires when the blob has been written to the
                 backend storage.
        """

    def delete_blob(user, blob_id, namespace=''):
        """
        Delete a blob from the backend storage.

        :param user: The id of the user who owns the blob.
        :type user: str
        :param blob_id: The id of the blob.
        :type blob_id: str
        :param namespace: An optional namespace for the blob.
        :type namespace: str
        """

    def get_blob_size(user, blob_id, namespace=''):
        """
        Get the size of a blob.

        :param user: The id of the user who owns the blob.
        :type user: str
        :param blob_id: The id of the blob.
        :type blob_id: str
        :param namespace: An optional namespace for the blob.
        :type namespace: str

        :return: The size of the blob.
        :rtype: int
        """

    def count(user, namespace=''):
        """
        Count the total number of blobs.

        :param user: The id of the user who owns the blob.
        :type user: str
        :param namespace: Restrict the count to a certain namespace.
        :type namespace: str

        :return: The number of blobs in the backend storage, possibly
                 restricted to a certain namespace.
        :rtype: int
        """

    def list_blobs(user, request, namespace='', order_by=None, deleted=False,
                   filter_flag=None):
        """
        List the blobs stored in the backend.

        The resulting list can be ordered by date, filtered by namespace or
        flag, and include deleted items or not.

        :param user: The id of the user who owns the blob.
        :type user: str
        :param request: A representation of all of the information about the
            request that is being made.
        :type request: twisted.web.server.Request
        :param namespace: Restrict the count to a certain namespace.
        :type namespace: str

        :param order_by: 'date' (equivalent to '+date') or  '-date', to sort
            ascending or descending by date, respectivelly.
        :type order_by: str
        :param deleted: Whether to include deleted items in the result.
        :type deleted: bool
        :param filter_flag: If given, only results flagged with that flag will
            be returned.
        :type filter_flag: str

        :return: A JSON list of blob ids, optionally ordered and/or restricted
                 by namespace.
        :rtype: str
        """

    def get_total_storage(user):
        """
        Get the size used by a given user as the sum of all the blobs stored
        under all that user's namespaces.

        :param user: The id of a user.
        :type user: str

        :return: The size in units of 1024 bytes.
        :rtype: int
        """

    def get_tag(user, blob_id, namespace=''):
        """
        Get the tag of a blob.

        :param blob_id: The id of the blob.
        :type blob_id: str
        :param namespace: An optional namespace for the blob.
        :type namespace: str

        :return: The tag of the blob.
        :rtype: str
        """

    def get_flags(user, blob_id, request, namespace=''):
        """
        Get the flags for a blob.

        :param user: The id of the user who owns the blob.
        :type user: str
        :param blob_id: The id of the blob.
        :type blob_id: str
        :param request: A representation of all of the information about the
            request that is being made.
        :type request: twisted.web.server.Request
        :param namespace: An optional namespace for the blob.
        :type namespace: str

        :return: a JSON encoded string with a list of flags.
        :rtype: str
        """

    def set_flags(user, blob_id, request, namespace=''):
        """
        Set flags for a blob.

        The flags are expected to be send in the body of the request, as a JSON
        list of strings.

        :param user: The id of the user who owns the blob.
        :type user: str
        :param blob_id: The id of the blob.
        :type blob_id: str
        :param request: A representation of all of the information about the
            request that is being made.
        :type request: twisted.web.server.Request
        :param namespace: An optional namespace for the blob.
        :type namespace: str

        :return: A string describing an error or ``None`` in case of success.
        :rtype: str
        """
