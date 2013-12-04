function(head, req) {
    var row;
    var rows=[];
    var i = 1;
    var gen = 1;
    if (req.query.gen)
        gen = parseInt(req.query['gen']);
    // fetch all rows
    while(row = getRow())
        rows.push(row);
    if (gen <= rows.length)
        send(JSON.stringify({
            "generation": gen,
            "doc_id": rows[gen-1]['id'],
            "transaction_id": rows[gen-1]['value'],
        }));
    else
        send('{}');
}
