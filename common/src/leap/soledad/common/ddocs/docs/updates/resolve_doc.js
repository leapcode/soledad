function(doc, req){
    /* we expect to receive the following in `req.body`:
     * {
     *     'couch_rev': '<couch_rev>',
     *     'conflicts': '<base64 encoded conflicts>',
     * }
     */
    var body = JSON.parse(req.body);

    // fail if no document was given
    if (!doc) {
        return [null, 'document does not exist']
    } 

    // fail if couch revisions do not match
    if (body['couch_rev'] != null
        && doc['_rev'] != body['couch_rev']) {
        return [null, 'revision conflict']
    }

    // fail if conflicts were not sent
    if (body['conflicts'] == null)
        return [null, 'missing conflicts']

    // save conflicts as attachment if they were sent
    if (body['conflicts'] != null) {
        if (!doc._attachments)
            doc._attachments = {};
        doc._attachments.u1db_conflicts = {
            content_type: "application/octet-stream",
            data: body['conflicts']  // should be base64 encoded
        }
    }
    // or delete attachment if there are no conflicts
    else if (doc._attachments && doc._attachments.u1db_conflicts)
        delete doc._attachments.u1db_conflicts;

    return [doc, 'ok'];
}
