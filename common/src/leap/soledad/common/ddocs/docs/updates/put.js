function(doc, req){
    /* we expect to receive the following in `req.body`:
     * {
     *     'couch_rev': '<couch_rev>',
     *     'u1db_rev': '<u1db_rev>',
     *     'content': '<base64 encoded content>',
     *     'trans_id': '<reansaction_id>'
     *     'conflicts': '<base64 encoded conflicts>',
     *     'update_conflicts': <boolean>
     * }
     */
    var body = JSON.parse(req.body);

    // create a new document document
    if (!doc) {
        doc = {}
        doc['_id'] = req['id'];
    }
    // or fail if couch revisions do not match
    else if (doc['_rev'] != body['couch_rev']) {
        // of fail if revisions do not match
        return [null, 'revision conflict']
    }

    // store u1db rev
    doc.u1db_rev = body['u1db_rev'];

    // save content as attachment
    if (body['content'] != null) {
        // save u1db content as attachment
        if (!doc._attachments)
            doc._attachments = {};
        doc._attachments.u1db_content =  {
            content_type: "application/octet-stream",
            data: body['content']  // should be base64 encoded
        };
    }
    // or delete the attachment if document is tombstone
    else if (doc._attachments &&
             doc._attachments.u1db_content)
        delete doc._attachments.u1db_content;

    // store the transaction id
    if (!doc.u1db_transactions)
        doc.u1db_transactions = [];
    var d = new Date();
    doc.u1db_transactions.push([d.getTime(), body['trans_id']]);

    // save conflicts as attachment if they were sent
    if (body['update_conflicts'])
        if (body['conflicts'] != null) {
            if (!doc._attachments)
                doc._attachments = {};
            doc._attachments.u1db_conflicts = {
                content_type: "application/octet-stream",
                data: body['conflicts']  // should be base64 encoded
            }
        } else {
            if(doc._attachments && doc._attachments.u1db_conflicts)
                delete doc._attachments.u1db_conflicts
        }

    return [doc, 'ok'];
}
