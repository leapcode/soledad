function(head, req) {
    var row;
    var gen = 1;
    var old_gen = 0;
    if (req.query.old_gen)
        old_gen = parseInt(req.query['old_gen']);
    send('{"transactions":[\n');
    // fetch all rows
    while(row = getRow()) {
        if (gen > old_gen) {
            if (gen > old_gen+1)
                send(',\n');
            send(JSON.stringify({
                "generation": gen,
                "doc_id": row["id"],
                "transaction_id": row["value"]
            }));
        }
        gen++;
    }
    send('\n]}');
}
