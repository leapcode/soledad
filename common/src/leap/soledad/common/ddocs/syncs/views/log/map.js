function(doc) {
    if (doc._id == 'u1db_sync_log') {
        if (doc.syncs)
            doc.syncs.forEach(function (entry) {
                emit(entry[0],
                    {
                        'known_generation': entry[1],
                        'known_transaction_id': entry[2]
                    });
            });
    }
}
