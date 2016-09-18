# -*- coding: utf-8 -*-
# interfaces.py
# Copyright (C) 2014 LEAP
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
Interfaces used by the Soledad Client.
"""
from zope.interface import Interface, Attribute

#
# Plugins
#


class ISoledadPostSyncPlugin(Interface):
    """
    I implement the minimal methods and attributes for a plugin that can be
    called after a soledad synchronization has ended.
    """

    def process_received_docs(self, doc_id_list):
        """
        Do something with the passed list of doc_ids received after the last
        sync.

        :param doc_id_list: a list of strings for the received doc_ids
        """

    watched_doc_types = Attribute("""
        a tuple of the watched doc types for this plugin. So far, the
        `doc-types` convention is just the preffix of the doc_id, which is
        basically its first character, followed by a dash. So, for instance,
        `M-` is used for meta-docs in mail, and `F-` is used for flag-docs in
        mail. For now there's no central register of all the doc-types
        used.""")


#
# Soledad storage
#

class ILocalStorage(Interface):
    """
    I implement core methods for the u1db local storage of documents and
    indexes.
    """
    local_db_path = Attribute(
        "The path for the local database replica")
    local_db_file_name = Attribute(
        "The name of the local SQLCipher U1DB database file")
    uuid = Attribute("The user uuid")
    default_prefix = Attribute(
        "Prefix for default values for path")

    def put_doc(self, doc):
        """
        Update a document in the local encrypted database.

        :param doc: the document to update
        :type doc: SoledadDocument

        :return:
            a deferred that will fire with the new revision identifier for
            the document
        :rtype: Deferred
        """

    def delete_doc(self, doc):
        """
        Delete a document from the local encrypted database.

        :param doc: the document to delete
        :type doc: SoledadDocument

        :return:
            a deferred that will fire with ...
        :rtype: Deferred
        """

    def get_doc(self, doc_id, include_deleted=False):
        """
        Retrieve a document from the local encrypted database.

        :param doc_id: the unique document identifier
        :type doc_id: str
        :param include_deleted:
            if True, deleted documents will be returned with empty content;
            otherwise asking for a deleted document will return None
        :type include_deleted: bool

        :return:
            A deferred that will fire with the document object, containing a
            SoledadDocument, or None if it could not be found
        :rtype: Deferred
        """

    def get_docs(self, doc_ids, check_for_conflicts=True,
                 include_deleted=False):
        """
        Get the content for many documents.

        :param doc_ids: a list of document identifiers
        :type doc_ids: list
        :param check_for_conflicts: if set False, then the conflict check will
            be skipped, and 'None' will be returned instead of True/False
        :type check_for_conflicts: bool

        :return:
            A deferred that will fire with an iterable giving the Document
            object for each document id in matching doc_ids order.
        :rtype: Deferred
        """

    def get_all_docs(self, include_deleted=False):
        """
        Get the JSON content for all documents in the database.

        :param include_deleted: If set to True, deleted documents will be
                                returned with empty content. Otherwise deleted
                                documents will not be included in the results.
        :return:
            A deferred that will fire with (generation, [Document]): that is,
            the current generation of the database, followed by a list of all
            the documents in the database.
        :rtype: Deferred
        """

    def create_doc(self, content, doc_id=None):
        """
        Create a new document in the local encrypted database.

        :param content: the contents of the new document
        :type content: dict
        :param doc_id: an optional identifier specifying the document id
        :type doc_id: str

        :return:
            A deferred tht will fire with the new document (SoledadDocument
            instance).
        :rtype: Deferred
        """

    def create_doc_from_json(self, json, doc_id=None):
        """
        Create a new document.

        You can optionally specify the document identifier, but the document
        must not already exist. See 'put_doc' if you want to override an
        existing document.
        If the database specifies a maximum document size and the document
        exceeds it, create will fail and raise a DocumentTooBig exception.

        :param json: The JSON document string
        :type json: str
        :param doc_id: An optional identifier specifying the document id.
        :type doc_id:
        :return:
            A deferred that will fire with the new document (A SoledadDocument
            instance)
        :rtype: Deferred
        """

    def create_index(self, index_name, *index_expressions):
        """
        Create an named index, which can then be queried for future lookups.
        Creating an index which already exists is not an error, and is cheap.
        Creating an index which does not match the index_expressions of the
        existing index is an error.
        Creating an index will block until the expressions have been evaluated
        and the index generated.

        :param index_name: A unique name which can be used as a key prefix
        :type index_name: str
        :param index_expressions:
            index expressions defining the index information.
        :type index_expressions: dict

            Examples:

            "fieldname", or "fieldname.subfieldname" to index alphabetically
            sorted on the contents of a field.

            "number(fieldname, width)", "lower(fieldname)"
        """

    def delete_index(self, index_name):
        """
        Remove a named index.

        :param index_name: The name of the index we are removing
        :type index_name: str
        """

    def list_indexes(self):
        """
        List the definitions of all known indexes.

        :return: A list of [('index-name', ['field', 'field2'])] definitions.
        :rtype: Deferred
        """

    def get_from_index(self, index_name, *key_values):
        """
        Return documents that match the keys supplied.

        You must supply exactly the same number of values as have been defined
        in the index. It is possible to do a prefix match by using '*' to
        indicate a wildcard match. You can only supply '*' to trailing entries,
        (eg 'val', '*', '*' is allowed, but '*', 'val', 'val' is not.)
        It is also possible to append a '*' to the last supplied value (eg
        'val*', '*', '*' or 'val', 'val*', '*', but not 'val*', 'val', '*')

        :param index_name: The index to query
        :type index_name: str
        :param key_values: values to match. eg, if you have
                           an index with 3 fields then you would have:
                           get_from_index(index_name, val1, val2, val3)
        :type key_values: tuple
        :return: List of [Document]
        :rtype: list
        """

    def get_count_from_index(self, index_name, *key_values):
        """
        Return the count of the documents that match the keys and
        values supplied.

        :param index_name: The index to query
        :type index_name: str
        :param key_values: values to match. eg, if you have
                           an index with 3 fields then you would have:
                           get_from_index(index_name, val1, val2, val3)
        :type key_values: tuple
        :return: count.
        :rtype: int
        """

    def get_range_from_index(self, index_name, start_value, end_value):
        """
        Return documents that fall within the specified range.

        Both ends of the range are inclusive. For both start_value and
        end_value, one must supply exactly the same number of values as have
        been defined in the index, or pass None. In case of a single column
        index, a string is accepted as an alternative for a tuple with a single
        value. It is possible to do a prefix match by using '*' to indicate
        a wildcard match. You can only supply '*' to trailing entries, (eg
        'val', '*', '*' is allowed, but '*', 'val', 'val' is not.) It is also
        possible to append a '*' to the last supplied value (eg 'val*', '*',
        '*' or 'val', 'val*', '*', but not 'val*', 'val', '*')

        :param index_name: The index to query
        :type index_name: str
        :param start_values: tuples of values that define the lower bound of
            the range. eg, if you have an index with 3 fields then you would
            have: (val1, val2, val3)
        :type start_values: tuple
        :param end_values: tuples of values that define the upper bound of the
            range. eg, if you have an index with 3 fields then you would have:
            (val1, val2, val3)
        :type end_values: tuple
        :return: A deferred that will fire with a list of [Document]
        :rtype: Deferred
        """

    def get_index_keys(self, index_name):
        """
        Return all keys under which documents are indexed in this index.

        :param index_name: The index to query
        :type index_name: str
        :return:
            A deferred that will fire with a list of tuples of indexed keys.
        :rtype: Deferred
        """

    def get_doc_conflicts(self, doc_id):
        """
        Get the list of conflicts for the given document.

        :param doc_id: the document id
        :type doc_id: str

        :return:
            A deferred that will fire with a list of the document entries that
            are conflicted.
        :rtype: Deferred
        """

    def resolve_doc(self, doc, conflicted_doc_revs):
        """
        Mark a document as no longer conflicted.

        :param doc: a document with the new content to be inserted.
        :type doc: SoledadDocument
        :param conflicted_doc_revs:
            A deferred that will fire with a list of revisions that the new
            content supersedes.
        :type conflicted_doc_revs: list
        """


class ISyncableStorage(Interface):
    """
    I implement methods to synchronize with a remote replica.
    """
    replica_uid = Attribute("The uid of the local replica")
    syncing = Attribute(
        "Property, True if the syncer is syncing.")
    token = Attribute("The authentication Token.")

    def sync(self):
        """
        Synchronize the local encrypted replica with a remote replica.

        This method blocks until a syncing lock is acquired, so there are no
        attempts of concurrent syncs from the same client replica.

        :param url: the url of the target replica to sync with
        :type url: str

        :return:
            A deferred that will fire with the local generation before the
            synchronisation was performed.
        :rtype: str
        """

    def stop_sync(self):
        """
        Stop the current syncing process.
        """


class ISecretsStorage(Interface):
    """
    I implement methods needed for initializing and accessing secrets, that are
    synced against the Shared Recovery Database.
    """
    secrets_file_name = Attribute(
        "The name of the file where the storage secrets will be stored")

    storage_secret = Attribute("")
    remote_storage_secret = Attribute("")
    shared_db = Attribute("The shared db object")

    # XXX this used internally from secrets, so it might be good to preserve
    # as a public boundary with other components.

    # We should also probably document its interface.
    secrets = Attribute("A SoledadSecrets object containing access to secrets")

    def init_shared_db(self, server_url, uuid, creds):
        """
        Initialize the shared recovery database.

        :param server_url:
        :type server_url:
        :param uuid:
        :type uuid:
        :param creds:
        :type creds:
        """

    def change_passphrase(self, new_passphrase):
        """
        Change the passphrase that encrypts the storage secret.

        :param new_passphrase: The new passphrase.
        :type new_passphrase: unicode

        :raise NoStorageSecret: Raised if there's no storage secret available.
        """

    # XXX not in use. Uncomment if we ever decide to allow
    # multiple secrets.
    # secret_id = Attribute("The id of the storage secret to be used")
