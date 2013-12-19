function(doc) {
    if (doc.u1db_rev) {
        var is_tombstone = true;
        var has_conflicts = false;
        if (doc._attachments) {
            if (doc._attachments.u1db_content)
                is_tombstone = false;
            if (doc._attachments.u1db_conflicts)
                has_conflicts = true;
        }
        emit(doc._id,
            {
                "couch_rev": doc._rev,
                "u1db_rev": doc.u1db_rev,
                "is_tombstone": is_tombstone,
                "has_conflicts": has_conflicts,
            }
        );
    }
}
