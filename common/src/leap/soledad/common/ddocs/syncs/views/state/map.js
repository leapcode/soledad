function(doc) {
  if (doc['_id'] == 'u1db_sync_state' && doc['ongoing_syncs'] != null)
    for (var source_replica_uid in doc['ongoing_syncs']) {
      var changes = doc['ongoing_syncs'][source_replica_uid]['changes_to_return'];
      if (changes == null)
        emit(source_replica_uid, null);
      else
        emit(
          source_replica_uid,
          {
            'gen': changes['gen'],
            'trans_id': changes['trans_id'],
            'number_of_changes': changes['changes_to_return'].length
          });
    }
}
