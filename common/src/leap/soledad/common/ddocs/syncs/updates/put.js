function(doc, req){
    if (!doc) {
        doc = {}
        doc['_id'] = 'u1db_sync_log';
        doc['syncs'] = [];
    }
    body = JSON.parse(req.body);
    // remove outdated info
    doc['syncs'] = doc['syncs'].filter(
        function (entry) {
            return entry[0] != body['other_replica_uid'];
        }
    );
    // store u1db rev
    doc['syncs'].push([
        body['other_replica_uid'],
        body['other_generation'],
        body['other_transaction_id']
    ]);
    return [doc, 'ok'];
}

