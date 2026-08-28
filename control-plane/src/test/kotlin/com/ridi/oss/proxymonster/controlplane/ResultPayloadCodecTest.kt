package com.ridi.oss.proxymonster.controlplane

import com.ridi.oss.proxymonster.analyzer.pb.MaskedDisposition
import com.ridi.oss.proxymonster.analyzer.pb.columnResource
import com.ridi.oss.proxymonster.analyzer.pb.relationIdentity
import com.ridi.oss.proxymonster.analyzer.pb.requireResultReadGrant
import com.ridi.oss.proxymonster.analyzer.pb.resultFingerprint
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * A stored result is encrypted at rest and outlives the process that wrote it, so its encoding has to be
 * one a DIFFERENT implementation can read — the control plane is being ported to Go. These pin the
 * protobuf round-trip and the legacy-JSON fallback that carries results written before the migration.
 */
class ResultPayloadCodecTest {

    private val fingerprint = resultFingerprint {
        grants.add(
            requireResultReadGrant {
                column = columnResource {
                    catalog = "def"
                    identity = relationIdentity {
                        schema = "bom"
                        table = "tb_user"
                        column = "email"
                    }
                }
                maskedDisposition = MaskedDisposition.MASKED_DISPOSITION_MASK_OUTPUT
                outputOrdinals.add(1)
            },
        )
    }

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
            resultFingerprint = fingerprint,
        )
        val decoded = ResultPayloadCodec.decode(ResultPayloadCodec.encode(original))
        assertEquals(original.columns, decoded.columns)
        assertEquals(original.rows, decoded.rows)
        assertNull(decoded.rowsAffected, "a row-returning statement has no affected-row count")
        assertEquals(original.resultFingerprint, decoded.resultFingerprint)
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
    fun `an empty fingerprint stays distinct from an absent one`() {
        // An EMPTY fingerprint means "a grant-less passthrough" and releases raw; an ABSENT one means the
        // result predates fingerprints and is unverifiable, so it must fail closed. Flattening the two
        // would release a legacy result as if it had been proven safe (decideResultView).
        val empty = ResultPayloadCodec.decode(
            ResultPayloadCodec.encode(
                DecryptedResult(columns = listOf("a"), rows = emptyList(), resultFingerprint = resultFingerprint {}),
            ),
        )
        assertEquals(0, empty.resultFingerprint?.grantsCount, "an empty fingerprint round-trips as present-but-empty")

        val legacy = ResultPayloadCodec.decode(
            ResultPayloadCodec.encode(DecryptedResult(columns = listOf("a"), rows = emptyList(), resultFingerprint = null)),
        )
        assertNull(legacy.resultFingerprint, "an absent fingerprint must not become an empty one")
    }

    @Test
    fun `a result written as kotlinx JSON before the migration still decodes`() {
        // A FROZEN literal, not a re-serialization: generating this with the same DecryptedResult.serializer()
        // that decode() falls back to would let both drift together and stay green while real pre-deploy
        // ciphertext failed. These are the exact bytes the pre-migration control plane wrote — kotlinx's
        // default Json (no pretty-print, nulls emitted, defaults omitted) with the ResultFingerprint proto
        // base64'd inside the string, which is what the old ResultFingerprintSerializer did.
        val legacyJson = """
            {"columns":["id","ssn"],"rows":[["1",null]],"resultFingerprint":"$LEGACY_FINGERPRINT_B64"}
        """.trimIndent().toByteArray(Charsets.UTF_8)

        val decoded = ResultPayloadCodec.decode(legacyJson)
        assertEquals(listOf("id", "ssn"), decoded.columns)
        assertEquals(listOf(listOf("1", null)), decoded.rows, "a legacy NULL cell must stay NULL")
        assertNull(decoded.rowsAffected, "rowsAffected was omitted as a default and must read back absent")
        assertEquals(fingerprint, decoded.resultFingerprint, "the base64'd proto must still parse")
    }

    private companion object {
        // The base64 the old serializer emitted for [fingerprint]. analyzer.proto is unchanged by this
        // migration, so these bytes are byte-identical to what a pre-migration deployment stored.
        const val LEGACY_FINGERPRINT_B64 = "CiMKHAoDZGVmEhUKA2JvbRIHdGJfdXNlchoFZW1haWwoAjIBAQ=="
    }

    @Test
    fun `a protobuf payload that begins with the JSON brace still decodes as protobuf`() {
        // `{` (0x7b) is a valid protobuf tag — field 15, the deprecated START_GROUP — so a payload from a
        // NEWER schema can legitimately begin with it and parse here as an unknown field. Deciding the
        // format by sniffing that byte would hand such a result to the JSON parser and fail a readable row;
        // parsing decides instead, protobuf first.
        val unknownFieldPayload = byteArrayOf(0x7b, 0x7c)
        assertEquals(
            '{'.code.toByte(), unknownFieldPayload[0],
            "this payload is exactly the ambiguous case: it starts with the JSON brace",
        )
        val decoded = ResultPayloadCodec.decode(unknownFieldPayload)
        assertEquals(emptyList(), decoded.columns, "an unknown-field-only message carries no columns")
        assertEquals(emptyList(), decoded.rows)
        assertNull(decoded.rowsAffected)
        assertNull(decoded.resultFingerprint, "no fingerprint means unverifiable, which fails closed at view")
    }

    @Test
    fun `bytes that are neither encoding fail rather than decoding to an empty result`() {
        // An empty result is a RELEASABLE value (a query that matched nothing), so a corrupt payload must
        // throw and surface as a failure — never decode to "no rows, no masked columns".
        assertFailsWith<Exception> { ResultPayloadCodec.decode("{ not valid json".toByteArray(Charsets.UTF_8)) }
    }
}
