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
    An interface for a BlobsBackend.
    """

    def read_blob(user, blob_id, request, namespace=''):
        """
        Read blob with a given blob_id, and write it to the passed request.

        :returns: a deferred that fires upon finishing.
        """

    def write_blob(user, blob_id, request, namespace=''):
        """
        Write blob to the storage, reading it from the passed request.

        :returns: a deferred that fires upon finishing.
        """

    def delete_blob(user, blob_id, namespace=''):
        """
        Delete the given blob_id.
        """

    def get_blob_size(user, blob_id, namespace=''):
        """
        Get the size of the given blob id.
        """

    def count(user, request, namespace=''):
        """
        Counts the total number of blobs.
        """

    def list_blobs(user, request, namespace='', order_by=None):
        """
        Returns a json-encoded list of ids from user's blobs storage,
        optionally ordered by order_by parameter and optionally restricted by
        namespace.

        :returns: a deferred that fires upon finishing.
        """

    def get_total_storage(user):
        """
        Get the size used by a given user as the sum of all the blobs stored
        unders its namespace.
        """

    def add_tag_header(user, blob_id, request, namespace=''):
        """
        Adds a header 'Tag' to the passed request object, containing the last
        16 bytes of the encoded blob, which according to the spec contains the
        tag.

        :returns: a deferred that fires upon finishing.
        """


class IIncomingBoxBackend(Interface):

    """
    An interface for an IncomingBoxBackend implementation.
    """

    def get_flags(user, blob_id, request, namespace=''):
        """
        Given a blob_id, return it's associated flags.

        :returns: a JSON encoded string with a list of flags.
        """

    def set_flags(self, user, blob_id, request, namespace=''):
        """
        Set flags for a blob_id.
        """

    def list_blobs(self, user, request, namespace='', order_by=None,
                   filter_flag=False):
        """
        Blobs listing with flags support. Accepts a filter_flag parameter,
        which is a flag that can be used to filter results matching it.

        :returns: a deferred that fires upon finishing.
        """
