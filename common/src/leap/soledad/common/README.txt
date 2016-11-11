Soledad common package
======================

This package contains Soledad bits used by both server and client.

Couch L2DB Backend
------------------

L2DB backends rely on some atomic operations that modify documents contents
and metadata (conflicts, transaction ids and indexes). The only atomic
operation in Couch is a document put, so every u1db atomic operation has to be
mapped to a couch document put.

The atomic operations in the U1DB SQLite reference backend implementation may
be identified by the use of a context manager to access the underlying
database. A listing of the methods involved in each atomic operation are
depiced below. The top-level elements correpond to the atomic operations that
have to be mapped, and items on deeper levels of the list have to be
implemented in a way that all changes will be pushed with just one operation.

    * _set_replica_uid
    * put_doc:
        * _get_doc
        * _put_and_update_indexes
            * insert/update the document
            * insert into transaction log
    * delete_doc
        * _get_doc
        * _put_and_update_indexes
    * get_doc_conflicts
        * _get_conflicts
    * _set_replica_gen_and_trans_id
        * _do_set_replica_gen_and_trans_id
    * _put_doc_if_newer
        * _get_doc
        * _validate_source (**)
            * _get_replica_gen_and_trans_id
        * cases:
            * is newer:
                * _prune_conflicts (**)
                    * _has_conflicts
                    * _delete_conflicts
                * _put_and_update_indexes
            * same content as:
                * _put_and_update_indexes
            * conflicted:
                * _force_doc_sync_conflict
                    * _prune_conflicts
                    * _add_conflict
                    * _put_and_update_indexes
        * _do_set_replica_gen_and_trans_id
    * resolve_doc
        * _get_doc
        * cases:
            * doc is superseded
                * _put_and_update_indexes
            * else
                * _add_conflict
        * _delete_conflicts
    * delete_index
    * create_index

Couch views and update functions are used in order to achieve atomicity on the
Couch backend. Transactions are stored in the `u1db_transactions` field of the
couch document. Document's content and conflicted versions are stored as couch
document attachments with names, respectivelly, `u1db_content` and
`u1db_conflicts`.

A map of methods and couch query URI can be found on the `./ddocs/README.txt`
document.

Notes:

  * Currently, the couch backend does not implement indexing, so what is
    depicted as `_put_and_update_indexes` above will be found as `_put_doc` in
    the backend.

  * Conflict updates are part of document put using couch update functions,
    and as such are part of the same atomic operation as document put.
