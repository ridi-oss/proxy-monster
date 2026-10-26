package com.ridi.oss.proxymonster.controlplane

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertFailsWith

/**
 * A stored result is encrypted at rest and outlives the process that wrote it, so its encoding has to be
 * one a DIFFERENT implementation can read — the control plane is being ported to Go. These pin the
 * protobuf round-trip.
 */
class ResultPayloadCodecTest {

    @Test
    fun `protobuf round-trips every field, including the ones an empty-vs-absent bug would flatten`() {
        val original = DecryptedResult(
            columns = listOf("id", "email", "note"),
            // A NULL cell must not read back as the empty string: a masked-to-NULL value and an empty
            // value are different answers, and the mask is what produces the former.
            rows = listOf(
                listOf("1", "a@x", null),
                listOf("2", null, ""),
            ),
            rowsAffected = null,
        )
        val decoded = ResultPayloadCodec.decode(ResultPayloadCodec.encode(original))
        assertEquals(original.columns, decoded.columns)
        assertEquals(original.rows, decoded.rows)
        assertNull(decoded.rowsAffected, "a row-returning statement has no affected-row count")
    }

    @Test
    fun `a DML result keeps a zero affected-row count distinct from absent`() {
        // 0 affected rows is a real answer ("matched nothing"), so it must survive as 0 rather than
        // collapsing into the absent case a row-returning statement uses.
        val zero = ResultPayloadCodec.decode(
            ResultPayloadCodec.encode(DecryptedResult(columns = emptyList(), rows = emptyList(), rowsAffected = 0)),
        )
        assertEquals(0, zero.rowsAffected)
        val absent = ResultPayloadCodec.decode(
            ResultPayloadCodec.encode(DecryptedResult(columns = emptyList(), rows = emptyList(), rowsAffected = null)),
        )
        assertNull(absent.rowsAffected)
    }

    @Test
    fun `bytes that are not a stored result fail rather than decoding to an empty result`() {
        // An empty result is a RELEASABLE value (a query that matched nothing), so a corrupt payload must
        // throw and surface as a failure — never decode to "no rows, no masked columns".
        assertFailsWith<Exception> { ResultPayloadCodec.decode("{ not valid json".toByteArray(Charsets.UTF_8)) }
    }
}
