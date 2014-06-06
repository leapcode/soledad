/**
 * This update handler stores information about ongoing synchronization
 * attempts from distinct source replicas.
 *
 * Normally, u1db synchronization occurs during one POST request. In order to
 * split that into many serial POST requests, we store the state of each sync
 * in the server, using a document with id 'u1db_sync_state'.  To identify
 * each sync attempt, we use a sync_id sent by the client. If we ever receive
 * a new sync_id, we trash current data for that source replica and start
 * over.
 *
 * We expect the following in the document body:
 *
 * {
 *     'source_replica_uid': '<source_replica_uid>',
 *     'sync_id': '<sync_id>',
 *     'seen_ids': [['<doc_id>', <at_gen>], ...],     // optional
 *     'changes_to_return': [                         // optional
 *         'gen': <gen>,
 *         'trans_id': '<trans_id>',
 *         'changes_to_return': [[<doc_id>', <gen>, '<trans_id>'], ...]
 *     ],
 * }
 *
 * The format of the final document stored on server is:
 *
 * {
 *     '_id': '<str>',
 *     '_rev' '<str>',
 *     'ongoing_syncs': {
 *         '<source_replica_uid>': {
 *             'sync_id': '<sync_id>',
 *             'seen_ids': [['<doc_id>', <at_gen>[, ...],
 *             'changes_to_return': {
 *                  'gen': <gen>,
 *                  'trans_id': '<trans_id>',
 *                  'changes_to_return': [
 *                          ['<doc_id>', <gen>, '<trans_id>'],
 *                          ...,
 *                  ],
 *             },
 *         },
 *         ... // info about other source replicas here
 *     }
 * }
 */
function(doc, req) {

    // prevent updates to alien documents
    if (doc != null && doc['_id'] != 'u1db_sync_state')
        return [null, 'invalid data'];

    // create the document if it doesn't exist
    if (!doc)
        doc = {
            '_id': 'u1db_sync_state',
            'ongoing_syncs': {},
        };

    // parse and validate incoming data
    var body = JSON.parse(req.body);
    if (body['source_replica_uid'] == null)
        return [null, 'invalid data'];
    var source_replica_uid = body['source_replica_uid'];

    if (body['sync_id'] == null)
        return [null, 'invalid data'];
    var sync_id = body['sync_id'];

    // trash outdated sync data for that replica if that exists
    if (doc['ongoing_syncs'][source_replica_uid] != null &&
            doc['ongoing_syncs'][source_replica_uid]['sync_id'] != sync_id)
        delete doc['ongoing_syncs'][source_replica_uid];

    // create an entry for that source replica
    if (doc['ongoing_syncs'][source_replica_uid] == null)
        doc['ongoing_syncs'][source_replica_uid] = {
            'sync_id': sync_id,
            'seen_ids': {},
            'changes_to_return': null,
        };

    // incoming meta-data values should be exclusive, so we count how many
    // arrived and deny to accomplish the transaction if the count is high.
    var incoming_values = 0;
    var info = doc['ongoing_syncs'][source_replica_uid]

    // add incoming seen id
    if ('seen_id' in body) {
        info['seen_ids'][body['seen_id'][0]] = body['seen_id'][1];
        incoming_values += 1;
    }

    // add incoming changes_to_return
    if ('changes_to_return' in body) {
        info['changes_to_return'] = body['changes_to_return'];
        incoming_values += 1;
    }

    if (incoming_values != 1)
        return [null, 'invalid data'];

    return [doc, 'ok'];
}

