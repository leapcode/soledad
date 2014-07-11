/**
 * The u1db_sync_log document stores both the actual sync log and a list of
 * pending updates to the log, in case we receive incoming documents out of
 * the correct order (i.e. if there are parallel PUTs during the sync
 * process).
 *
 * The structure of the document is the following:
 *
 *     {
 *         'syncs': [
 *             ['<replica_uid>', <gen>, '<trans_id>'],
 *             ... 
 *         ],
 *         'pending': {
 *             'other_replica_uid': {
 *                 'sync_id': '<sync_id>',
 *                 'log': [[<gen>, '<trans_id>'], ...]
 *             },
 *             ...
 *         }
 *     }
 *
 * The update function below does the following:
 *
 *   0. If we do not receive a sync_id, we just update the 'syncs' list with
 *      the incoming info about the source replica state.
 *
 *   1. Otherwise, if the incoming sync_id differs from current stored
 *      sync_id, then we assume that the previous sync session for that source
 *      replica was interrupted and discard all pending data.
 *
 *   2. Then we append incoming info as pending data for that source replica
 *      and current sync_id, and sort the pending data by generation.
 *
 *   3. Then we go through pending data and find the most recent generation
 *      that we can use to update the actual sync log.
 *
 *   4. Finally, we insert the most up to date information into the sync log.
 */
function(doc, req){

    // create the document if it doesn't exist
    if (!doc) {
        doc = {}
        doc['_id'] = 'u1db_sync_log';
        doc['syncs'] = [];
    }

    // get and validate incoming info
    var body = JSON.parse(req.body);
    var other_replica_uid = body['other_replica_uid'];
    var other_generation = parseInt(body['other_generation']);
    var other_transaction_id = body['other_transaction_id']
    var sync_id = body['sync_id'];
    var number_of_docs = body['number_of_docs'];
    var doc_idx = body['doc_idx'];

    // parse integers
    if (number_of_docs != null)
        number_of_docs = parseInt(number_of_docs);
    if (doc_idx != null)
        doc_idx = parseInt(doc_idx);

    if (other_replica_uid == null
            || other_generation == null
            || other_transaction_id == null)
        return [null, 'invalid data'];

    // create slot for pending logs
    if (doc['pending'] == null)
        doc['pending'] = {};

    // these are the values that will be actually inserted
    var current_gen = other_generation;
    var current_trans_id = other_transaction_id;

    /*------------- Wait for sequential values before storing -------------*/

    // we just try to obtain pending log if we received a sync_id
    if (sync_id != null) {

        // create slot for current source and sync_id pending log
        if (doc['pending'][other_replica_uid] == null
                || doc['pending'][other_replica_uid]['sync_id'] != sync_id) {
            doc['pending'][other_replica_uid] = {
                'sync_id': sync_id,
                'log': [],
                'last_doc_idx': 0,
            }
        }

        // append incoming data to pending log
        doc['pending'][other_replica_uid]['log'].push([
            other_generation,
            other_transaction_id,
            doc_idx,
        ])

        // sort pending log according to generation
        doc['pending'][other_replica_uid]['log'].sort(function(a, b) {
            return a[0] - b[0];
        });

        // get most up-to-date information from pending log
        var last_doc_idx = doc['pending'][other_replica_uid]['last_doc_idx'];
        var pending_idx = doc['pending'][other_replica_uid]['log'][0][2];

        current_gen = null;
        current_trans_id = null;

        while (last_doc_idx + 1 == pending_idx) {
            pending = doc['pending'][other_replica_uid]['log'].shift()
            current_gen = pending[0];
            current_trans_id = pending[1];
            last_doc_idx = pending[2]
            if (doc['pending'][other_replica_uid]['log'].length == 0)
                break;
            pending_idx = doc['pending'][other_replica_uid]['log'][0][2];
        }

        // leave the sync log untouched if we still did not receive enough docs
        if (current_gen == null)
            return [doc, 'ok'];

        // update last index of received doc
        doc['pending'][other_replica_uid]['last_doc_idx'] = last_doc_idx;

        // eventually remove all pending data from that replica
        if (last_doc_idx == number_of_docs)
            delete doc['pending'][other_replica_uid]
    }

    /*--------------- Store source replica info on sync log ---------------*/

    // remove outdated info
    doc['syncs'] = doc['syncs'].filter(
        function (entry) {
            return entry[0] != other_replica_uid;
        }
    );

    // store in log
    doc['syncs'].push([
        other_replica_uid,
        current_gen,
        current_trans_id 
    ]);

    return [doc, 'ok'];
}

