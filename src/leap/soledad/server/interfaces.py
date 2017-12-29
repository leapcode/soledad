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

    There might be concurrent calls to methods that modify the same blob, so
    it's the backend implementation's responsibility to ensure isolation of
    such actions.
    """

    def read_blob(user, blob_id, consumer, namespace='', range=None):
        """
        Read a blob from the backend storage.

        :param user: The id of the user who owns the blob.
        :type user: str
        :param blob_id: The id of the blob.
        :type blob_id: str
        :param consumer: The object to write data to.
        :type consumer: twisted.internet.interfaces.IConsumer provider
        :param namespace: An optional namespace for the blob.
        :type namespace: str
        :param range: An optional tuple indicating start and end position of
            the blob to be produced.
        :type range: (int, int)

        :return: A deferred that fires when the blob has been written to the
            consumer.
        :rtype: twisted.internet.defer.Deferred

        :raise BlobNotFound: Raised (asynchronously) when the blob was not
            found in the backend.
        """

    def write_blob(user, blob_id, producer, namespace=''):
        """
        Write a blob to the backend storage.

        :param user: The id of the user who owns the blob.
        :type user: str
        :param blob_id: The id of the blob.
        :type blob_id: str
        :param producer: The object to read data from.
        :type producer: twisted.internet.interfaces.IProducer provider
        :param namespace: An optional namespace for the blob.
        :type namespace: str

        :return: A deferred that fires when the blob has been written to the
                 backend storage.
        :rtype: twisted.internet.defer.Deferred

        :raise BlobExists: Raised (asynchronously) when a blob with that id
            already exists.

        :raise QuotaExceeded: Raised (asynchronously) when the quota for that
            user was exceeded.
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

        :return: A deferred that fires when the blob has been deleted.
        :rtype: twisted.internet.defer.Deferred

        :raise BlobNotFound: Raised (asynchronously) when the blob was not
            found in the backend.
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

        :return: A deferred that fires with the size of the blob.
        :rtype: twisted.internet.defer.Deferred

        :raise BlobNotFound: Raised (asynchronously) when the blob was not
            found in the backend.
        """

    def count(user, namespace=''):
        """
        Count the total number of blobs.

        :param user: The id of the user who owns the blob.
        :type user: str
        :param namespace: Restrict the count to a certain namespace.
        :type namespace: str

        :return: A deferred that fires with the number of blobs in the backend
            storage, possibly restricted to a certain namespace.
        :rtype: twisted.internet.defer.Deferred
        """

    def list_blobs(user, namespace='', order_by=None, deleted=False,
                   filter_flag=None):
        """
        List the blobs stored in the backend.

        The resulting list can be ordered by date, filtered by namespace or
        flag, and include deleted items or not.

        :param user: The id of the user who owns the blob.
        :type user: str
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

        :return: A list of blob ids, optionally ordered and/or restricted by
                 namespace.
        :rtype: list of str

        :return: A deferred that fires with a list of blob ids, optionally
            ordered and/or restricted by namespace.
        :rtype: twisted.internet.defer.Deferred
        """

    def get_total_storage(user):
        """
        Get the size used by a given user as the sum of all the blobs stored
        under all that user's namespaces.

        :param user: The id of a user.
        :type user: str

        :return: The size in units of 1024 bytes.
        :rtype: int

        :return: A deferred that fires with the amount of storage used in units
            of 1024 bytes.
        :rtype: twisted.internet.defer.Deferred
        """

    def get_tag(user, blob_id, namespace=''):
        """
        Get the tag of a blob.

        :param blob_id: The id of the blob.
        :type blob_id: str
        :param namespace: An optional namespace for the blob.
        :type namespace: str

        :return: A deferred that fires with the tag of the blob.
        :rtype: twisted.internet.defer.Deferred

        :raise BlobNotFound: Raised (asynchronously) when the blob was not
            found in the backend.
        """

    def get_flags(user, blob_id, namespace=''):
        """
        Get the flags for a blob.

        :param user: The id of the user who owns the blob.
        :type user: str
        :param blob_id: The id of the blob.
        :type blob_id: str
        :param namespace: An optional namespace for the blob.
        :type namespace: str

        :return: A deferred that fires with the list of flags for a blob.
        :rtype: twisted.internet.defer.Deferred

        :raise BlobNotFound: Raised (asynchronously) when the blob was not
            found in the backend.
        """

    def set_flags(user, blob_id, flags, namespace=''):
        """
        Set flags for a blob.

        :param user: The id of the user who owns the blob.
        :type user: str
        :param blob_id: The id of the blob.
        :type blob_id: str
        :param flags: The list of flags to be set.
        :type flags: list of str
        :param namespace: An optional namespace for the blob.
        :type namespace: str

        :return: A deferred that fires when the flags have been set.
        :rtype: twisted.internet.defer.Deferred

        :raise BlobNotFound: Raised (asynchronously) when the blob was not
            found in the backend.

        :raise InvalidFlag: Raised (asynchronously) when one of the flags
            passed is invalid.
        """
