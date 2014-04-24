function(doc) {
  if (doc['_id'] == 'u1db_sync_state' && doc['ongoing_syncs'] != null)
    for (var source_replica_uid in doc['ongoing_syncs'])
      emit(
        source_replica_uid,
        {
          'seen_ids': doc['ongoing_syncs'][source_replica_uid]['seen_ids'],
        });
}
