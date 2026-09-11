package com.ridi.oss.proxymonster.controlplane.support

import com.ridi.oss.proxymonster.grpc.ResultCaps
import com.ridi.oss.proxymonster.grpc.resultCaps
import com.ridi.oss.proxymonster.grpc.rowsBytes

/** The proxy's shipped default cap table, for a stored result a test seeds and later views. */
internal val TEST_RESULT_CAPS: ResultCaps = resultCaps {
    default = rowsBytes { rows = 5_000; bytes = 50_000_000 }
    byTag.put("pii", rowsBytes { rows = 500; bytes = 5_000_000 })
}
