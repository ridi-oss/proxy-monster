package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.grpc.ObjectRef

/** The dotted path the catalog index and the Cedar refs key on: `catalog.schema.table`, plus `.column` for a column. */
internal val ObjectRef.key: String
    get() = if (column.isEmpty()) "$catalog.$schema.$table" else "$catalog.$schema.$table.$column"
