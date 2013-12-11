This directory holds a folder structure containing javascript files that
represent the design documents needed by the CouchDB U1DB backend. These files
are compiled into the `../ddocs.py` file by setuptools when creating the
source distribution.

The following table depicts the U1DB CouchDB backend method and the URI that
is queried to obtain/update data from/to the server.

   +----------------------------------+------------------------------------------------------------------+
   | u1db backend method              | URI                                                              |
   |----------------------------------+------------------------------------------------------------------|
   | _get_generation                  | _design/transactions/_list/generation/log                        |
   | _get_generation_info             | _design/transactions/_list/generation/log                        |
   | _get_trans_id_for_gen            | _design/transactions/_list/trans_id_for_gen/log                  |
   | _get_transaction_log             | _design/transactions/_view/log                                   |
   | _get_doc (*)                     | _design/docs/_view/get?key=<doc_id>                              |
   | _has_conflicts                   | _design/docs/_view/get?key=<doc_id>                              |
   | get_all_docs                     | _design/docs/_view/get                                           |
   | _put_doc                         | _design/docs/_update/put/<doc_id>                                |
   | _whats_changed                   | _design/transactions/_list/whats_changed/log?old_gen=<gen>       |
   | _get_conflicts (*)               | _design/docs/_view/conflicts?key=<doc_id>                        |
   | _get_replica_gen_and_trans_id    | _design/syncs/_view/log?other_replica_uid=<uid>                  |
   | _do_set_replica_gen_and_trans_id | _design/syncs/_update/put/u1db_sync_log                          |
   | _add_conflict                    | _design/docs/_update/add_conflict/<doc_id>                       |
   | _delete_conflicts                | _design/docs/_update/delete_conflicts/<doc_id>?doc_rev=<doc_rev> |
   | list_indexes                     | not implemented                                                  |
   | _get_index_definition            | not implemented                                                  |
   | delete_index                     | not implemented                                                  |
   | _get_indexed_fields              | not implemented                                                  |
   | _put_and_update_indexes          | not implemented                                                  |
   +----------------------------------+------------------------------------------------------------------+

(*) These methods also request CouchDB document attachments that store U1DB
    document contents.
