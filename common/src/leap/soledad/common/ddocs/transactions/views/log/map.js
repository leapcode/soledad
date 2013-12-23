function(doc) {
    if (doc.u1db_transactions)
        doc.u1db_transactions.forEach(function(t) {
            emit(t[0],  // use timestamp as key so the results are ordered
                 t[1]); // value is the transaction_id
        });
}
