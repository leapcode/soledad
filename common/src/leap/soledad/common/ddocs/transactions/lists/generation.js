function(head, req) {
    var row;
    var rows=[];
    // fetch all rows
    while(row = getRow()) {
        rows.push(row);
    }
    if (rows.length > 0)
        send(JSON.stringify({
            "generation": rows.length,
            "doc_id": rows[rows.length-1]['id'],
            "transaction_id": rows[rows.length-1]['value']
        }));
    else
        send(JSON.stringify({
            "generation": 0,
            "doc_id": "",
            "transaction_id": "",
        }));
}
