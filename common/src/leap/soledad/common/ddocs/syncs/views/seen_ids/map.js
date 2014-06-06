function(doc) {
  if (doc['_id'] == 'u1db_sync_state' && doc['ongoing_syncs'] != null)
    for (var source_replica_uid in doc['ongoing_syncs']) {
      var sync_id = doc['ongoing_syncs'][source_replica_uid]['sync_id'];
      emit(
        [source_replica_uid, sync_id],
        {
          'seen_ids': doc['ongoing_syncs'][source_replica_uid]['seen_ids'],
        });
    }
}
