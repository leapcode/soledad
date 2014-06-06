function(doc) {
  if (doc['_id'] == 'u1db_sync_state' && doc['ongoing_syncs'] != null)
    for (var source_replica_uid in doc['ongoing_syncs']) {
      var changes = doc['ongoing_syncs'][source_replica_uid]['changes_to_return'];
      var sync_id = doc['ongoing_syncs'][source_replica_uid]['sync_id'];
      if (changes == null)
        emit([source_replica_uid, sync_id, 0], null);
      else if (changes.length == 0)
        emit([source_replica_uid, sync_id, 0], []);
      else
        for (var i = 0; i < changes['changes_to_return'].length; i++)
          emit(
            [source_replica_uid, sync_id, i],
            {
              'gen': changes['gen'],
              'trans_id': changes['trans_id'],
              'next_change_to_return': changes['changes_to_return'][i],
            });
    }
}
