package com.ridi.oss.proxymonster.classification

/** PostgreSQL system columns (pg_attribute.attnum < 0): on every table, absent from information_schema. */
object PostgresSystemColumns {
    val byName: Map<String, String> = linkedMapOf(
        "ctid" to "tid",
        "xmin" to "xid",
        "xmax" to "xid",
        "cmin" to "cid",
        "cmax" to "cid",
        "tableoid" to "oid",
    )
}
